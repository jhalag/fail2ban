package fail2ban

// dummy handler implementing the fail2ban interace for tests.
type Fail2BanDummy struct {
}

func (u *Fail2BanDummy) ShouldAllow(remoteIP string) bool {
	return true
}

func (u *Fail2BanDummy) IsNotBanned(remoteIP string) bool {
	return true
}
