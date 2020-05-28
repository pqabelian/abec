package main

func ConfigTest(cfg *config) {
	cfg.MiningAddrs = make([]string, 1)
	cfg.MiningAddrs[0] = "abempk10123456789123456"
	cfg.SimNet = true
}

func Set4ABE(cfg *config) {
	cfg.forABE = true
}
