package main

import (
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"os"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
)

type Profile struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
}

type SavedProfile struct {
	Profile
	DeviceJSON string
	BrowserFp  string
}

const profileFile = "vk_profile.json"

func LoadProfileFromDisk() (*SavedProfile, error) {
	data, err := os.ReadFile(profileFile)
	if err != nil {
		return nil, err
	}
	var sp SavedProfile
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, err
	}
	return &sp, nil
}

func SaveProfileToDisk(sp SavedProfile) error {
	data, err := json.MarshalIndent(sp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(profileFile, data, 0644)
}

var profiles = []Profile{
	// Windows Chrome
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	// Windows Edge
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Microsoft Edge";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	// macOS Chrome
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},
	// Linux Chrome
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
}

func getRandomProfile() Profile {
	return profiles[mathrand.Intn(len(profiles))]
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func generateBrowserFp(profile Profile) string {
	// Generate a consistent fingerprint from profile data
	data := profile.UserAgent + profile.SecChUa + "1536x864x24"
	var h uint32
	for i := 0; i < len(data); i++ {
		h = h*31 + uint32(data[i])
	}
	return fmt.Sprintf("%016x%016x", h, h^0xdeadbeefcafe)
}

// randIntn is a package-level helper so all files can use it without importing math/rand directly.
func randIntn(n int) int {
	return mathrand.Intn(n)
}

var maleFirstNames = []string{
	"Александр", "Алексей", "Андрей", "Антон", "Арсений",
	"Артур", "Артём", "Богдан", "Валерий", "Василий",
	"Виктор", "Владислав", "Глеб", "Григорий", "Даниил",
	"Денис", "Дмитрий", "Евгений", "Егор", "Иван",
	"Игорь", "Илья", "Кирилл", "Леонид", "Максим",
	"Марк", "Матвей", "Михаил", "Никита", "Николай",
	"Олег", "Павел", "Пётр", "Роман", "Руслан",
	"Сергей", "Станислав", "Тимофей", "Фёдор",
}

var femaleFirstNames = []string{
	"Алина", "Алёна", "Анастасия", "Ангелина", "Анна",
	"Вера", "Вероника", "Виктория", "Дарья", "Ева",
	"Екатерина", "Елена", "Елизавета", "Ирина", "Кира",
	"Кристина", "Ксения", "Любовь", "Маргарита", "Марина",
	"Мария", "Милана", "Надежда", "Наталья", "Ольга",
	"Полина", "Светлана", "София", "Татьяна", "Юлия", "Яна",
}

var lastNames = []string{
	"Алексеев", "Андреев", "Антонов", "Баранов", "Белов",
	"Беляев", "Борисов", "Васильев", "Волков", "Воробьёв",
	"Григорьев", "Давыдов", "Егоров", "Жуков", "Зайцев",
	"Захаров", "Иванов", "Козлов", "Комаров", "Кузнецов",
	"Лебедев", "Макаров", "Медведев", "Михайлов", "Морозов",
	"Никитин", "Николаев", "Новиков", "Орлов", "Павлов",
	"Петров", "Попов", "Романов", "Семёнов", "Сергеев",
	"Смирнов", "Соколов", "Соловьёв", "Степанов", "Тарасов",
	"Фролов", "Фёдоров", "Яковлев",
}

func convertToFemaleSurname(surname string) string {
	if strings.HasSuffix(surname, "ий") || strings.HasSuffix(surname, "ый") || strings.HasSuffix(surname, "ой") {
		return surname[:len(surname)-4] + "ая"
	}
	if strings.HasSuffix(surname, "ов") || strings.HasSuffix(surname, "ев") ||
		strings.HasSuffix(surname, "ин") || strings.HasSuffix(surname, "ын") ||
		strings.HasSuffix(surname, "ёв") {
		return surname + "а"
	}
	return surname
}

func generateName() string {
	isFemale := mathrand.Intn(2) == 0

	var fn string
	if isFemale {
		fn = femaleFirstNames[mathrand.Intn(len(femaleFirstNames))]
	} else {
		fn = maleFirstNames[mathrand.Intn(len(maleFirstNames))]
	}

	if mathrand.Float32() < 0.3 {
		return fn
	}

	ln := lastNames[mathrand.Intn(len(lastNames))]
	if isFemale {
		ln = convertToFemaleSurname(ln)
	}
	return fmt.Sprintf("%s %s", fn, ln)
}
