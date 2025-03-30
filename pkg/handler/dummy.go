package handler

// Fail2BanDummy dummy handler implementing the fail2ban interface for tests.
// Will grant all requests and never ban.
type Fail2BanDummy struct {
}

func (u *Fail2BanDummy) ShouldAllow(remoteIP string) bool {
	return true
}

func (u *Fail2BanDummy) IsNotBanned(remoteIP string) bool {
	return true
}
