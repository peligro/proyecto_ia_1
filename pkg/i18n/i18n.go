package i18n

type Lang string

const (
	EN Lang = "en"
	ES Lang = "es"
	FR Lang = "fr"
	PT Lang = "pt"
	DE Lang = "de"
)

const DefaultLang = EN

var T *Translator

type Translator struct {
	lang Lang
	dict map[Lang]map[string]string
}

func NewTranslator(lang Lang) *Translator {
	if lang == "" {
		lang = DefaultLang
	}
	return &Translator{
		lang: lang,
		dict: loadDictionary(),
	}
}

func (t *Translator) Get(key string) string {
	if val, ok := t.dict[t.lang][key]; ok {
		return val
	}
	if val, ok := t.dict[EN][key]; ok {
		return val
	}
	return key
}

func (t *Translator) SetLang(lang Lang) {
	if lang == "" {
		lang = DefaultLang
	}
	t.lang = lang
}

func loadDictionary() map[Lang]map[string]string {
	return map[Lang]map[string]string{
		EN: enDict(),
		ES: esDict(),
		FR: frDict(),
		PT: ptDict(),
		DE: deDict(),
	}
}