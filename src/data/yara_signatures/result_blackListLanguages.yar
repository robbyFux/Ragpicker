rule BlackListLanguages {
	meta:
		description = "Unconventionial binary language"
	strings:
		$lang1 = "LANG_ARABIC"
		$lang2 = "LANG_BULGARIAN"
		$lang3 = "LANG_CHINESE"
		$lang4 = "LANG_ROMANIAN"
		$lang5 = "LANG_RUSSIAN"
		$lang6 = "LANG_CROATO-SERBIAN"
		$lang7 = "LANG_SLOVAK"
		$lang8 = "LANG_ALBANIAN"
		$lang9 = "LANG_TURKISH"
		$lang10 = "LANG_HEBREW"
		$lang11 = "LANG_KOREAN"
		$lang12 = "SUBLANG_ENGLISH_JAMAICA"
		$lang13 = "SUBLANG_ENGLISH_CARIBBEAN"
		$lang14 = "SUBLANG_ENGLISH_BELIZE"
		$lang15 = "SUBLANG_ENGLISH_TRINIDAD"
		$lang16 = "SUBLANG_ENGLISH_ZIMBABWE"
		$lang17 = "SUBLANG_ENGLISH_PHILIPPINES"
		$lang18 = "LANG_UZBEK"
		$lang19 = "LANG_VIETNAMESE"
		$lang20 = "LANG_UKRAINIAN"
		$lang21 = "LANG_TELUGU"
		$lang22 = "LANG_SYRIAC"
		$lang23 = "LANG_SERBIAN"
		$lang24 = "LANG_LATVIAN"
	condition:
    	any of them
}