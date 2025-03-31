package handler

// Fail2BanDummy dummy handler implementing the fail2ban interface for tests.
// Will simply return the values set on it each time it is called.
type Fail2BanDummy struct {
	Retval bool  // what value it should return
	Err    error // error to return, if any
}

func (u *Fail2BanDummy) ShouldAllow(remoteIP string) (bool, error) {
	return u.Retval, u.Err
}

func (u *Fail2BanDummy) IsNotBanned(remoteIP string) (bool, error) {
	return u.Retval, u.Err
}
