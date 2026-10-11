package humaaccesstoken

import (
	"net/http"
	"time"
)

// CookieAttrs carries deployment-dependent cookie attributes.
type CookieAttrs struct {
	Secure        bool
	Domain        string
	RefreshMaxAge time.Duration
}

// CreateCookie creates a cookie with standard security attributes.
func CreateCookie(name, value string, maxAge time.Duration, attrs CookieAttrs) http.Cookie {
	return http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  time.Now().Add(maxAge),
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Path:     "/",
		Domain:   attrs.Domain,
		Secure:   attrs.Secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// ExpireCookie returns a cookie that deletes name on the client.
func ExpireCookie(name string, attrs CookieAttrs) http.Cookie {
	return http.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
		Domain:   attrs.Domain,
		Secure:   attrs.Secure,
		SameSite: http.SameSiteLaxMode,
	}
}
