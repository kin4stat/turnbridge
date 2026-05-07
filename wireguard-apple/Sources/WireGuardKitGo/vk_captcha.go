package main

import (
	"context"
	"fmt"
	"log"
	mathrand "math/rand"
	neturl "net/url"
	"time"

	tlsclient "github.com/bogdanfinn/tls-client"
)

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	code := int(codeFloat)

	redirectURI, _ := errData["redirect_uri"].(string)
	captchaSid, _ := errData["captcha_sid"].(string)
	captchaImg, _ := errData["captcha_img"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	var sessionToken string
	if redirectURI != "" {
		if parsed, err := neturl.Parse(redirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	isSound, _ := errData["is_sound_captcha_available"].(bool)

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectURI:             redirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
}

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, useSliderPOC bool) (string, error) {
	time.Sleep(time.Duration(1500+mathrand.Intn(1000)) * time.Millisecond)

	if useSliderPOC {
		log.Printf("[STREAM %d] [Captcha] Solving captcha with slider POC...", streamID)
	} else {
		log.Printf("[STREAM %d] [Captcha] Solving captcha...", streamID)
	}

	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	var savedProfile *SavedProfile
	if sp, err := LoadProfileFromDisk(); err == nil {
		log.Printf("[STREAM %d] [Captcha] Using saved real browser profile", streamID)
		savedProfile = sp
	}

	// Try v2 solver first
	successToken, v2Err := solveVkCaptchaV2(ctx, captchaErr, streamID, client, profile, savedProfile)
	if v2Err == nil {
		log.Printf("[STREAM %d] [Captcha] v2 solver succeeded", streamID)
		return successToken, nil
	}
	log.Printf("[STREAM %d] [Captcha] v2 solver failed, falling back to legacy solver: %v", streamID, v2Err)

	// Legacy fallback
	return solveVkCaptchaLegacy(ctx, captchaErr, streamID, client, profile, savedProfile)
}

func solveVkCaptchaLegacy(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, savedProfile *SavedProfile) (string, error) {
	s := &captchaV2Session{ctx: ctx, client: client, profile: profile, savedProfile: savedProfile}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] PoW input: %s, difficulty: %d", streamID, bootstrap.PowInput, bootstrap.Difficulty)

	hash := solveCaptchaPoWV2(ctx, bootstrap.PowInput, bootstrap.Difficulty)
	if hash == "" {
		return "", fmt.Errorf("captcha PoW failed")
	}
	log.Printf("[STREAM %d] [Captcha] PoW solved: hash=%s", streamID, hash)

	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, streamID, s, savedProfile)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] Success! Got success_token", streamID)
	return successToken, nil
}

type captchaBootstrap struct {
	PowInput   string
	Difficulty int
}

func fetchCaptchaBootstrap(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile Profile) (*captchaBootstrap, error) {
	page, err := parseCaptchaV2PageFromURL(ctx, redirectURI, client, profile)
	if err != nil {
		return nil, err
	}
	return &captchaBootstrap{
		PowInput:   page.PowInput,
		Difficulty: page.PowDifficulty,
	}, nil
}

func parseCaptchaV2PageFromURL(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile Profile) (*captchaV2Page, error) {
	s := &captchaV2Session{ctx: ctx, client: client, profile: profile}
	html, err := s.fetchCaptchaHTML(redirectURI)
	if err != nil {
		return nil, err
	}
	return parseCaptchaV2Page(html)
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash string, streamID int, s *captchaV2Session, savedProfile *SavedProfile) (string, error) {
	base := captchaV2BaseValues(sessionToken)

	log.Printf("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	if _, err := s.captchaRequest("captchaNotRobot.settings", base); err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] Step 2/4: componentDone", streamID)
	browserFp, err := captchaV2BrowserFP()
	if err != nil {
		return "", err
	}
	if savedProfile != nil && savedProfile.BrowserFp != "" {
		browserFp = savedProfile.BrowserFp
	}

	deviceJSON := captchaV2DeviceInfo
	if savedProfile != nil && savedProfile.DeviceJSON != "" {
		deviceJSON = savedProfile.DeviceJSON
	}

	if _, err := s.captchaRequest("captchaNotRobot.componentDone", append(base,
		[2]string{"browser_fp", browserFp},
		[2]string{"device", deviceJSON},
	)); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	time.Sleep(time.Duration(1500+mathrand.Intn(1000)) * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 3/4: check (checkbox)", streamID)
	debugInfo := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	check, err := s.performCaptchaCheck(sessionToken, browserFp, hash, "{}", "[]", debugInfo)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	if check.Status == "OK" && check.SuccessToken != "" {
		log.Printf("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
		_, _ = s.captchaRequest("captchaNotRobot.endSession", base)
		return check.SuccessToken, nil
	}

	log.Printf("[STREAM %d] [Captcha] Checkbox failed, trying slider captcha...", streamID)

	sliderToken, sliderErr := s.solveSliderCaptcha(sessionToken, browserFp, hash, "", debugInfo)
	if sliderErr != nil {
		return "", fmt.Errorf("slider captcha also failed: %w", sliderErr)
	}

	log.Printf("[STREAM %d] [Captcha] Slider solved! endSession...", streamID)
	_, _ = s.captchaRequest("captchaNotRobot.endSession", base)
	return sliderToken, nil
}
