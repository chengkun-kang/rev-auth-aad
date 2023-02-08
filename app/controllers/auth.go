package controllers

import (
	"fmt"
	"strings"

	revauthaad "github.com/chengkun-kang/rev-auth-aad"
	"github.com/chengkun-kang/rev-auth-aad/app/models"
	mgodo "github.com/lujiacn/mgodo"
	"github.com/revel/revel"
	"github.com/revel/revel/cache"
)

type Auth struct {
	*revel.Controller
	mgodo.MgoController
}

// Authenticate with AAD
func (c *Auth) Authenticate(account, password string) revel.Result {
	//get nextUrl
	nextUrl := c.Params.Get("nextUrl")
	if nextUrl == "" {
		nextUrl = "/"
	}

	if account == "" || password == "" {
		c.Flash.Error("Please fill in account and password")
		return c.Redirect(c.Request.Referer())
	}

	authUser := revauthaad.AuthenticatePublicClient(account, password)
	currentUserIdentidy := strings.ToLower(authUser.Account)
	if !authUser.IsAuthenticated {
		//Save LoginLog
		loginLog := new(models.LoginLog)
		// loginLog.Account = account
		loginLog.Account = currentUserIdentidy
		loginLog.Status = "FAILURE"
		loginLog.IPAddress = c.Request.RemoteAddr
		mgodo.New(c.MgoSession, loginLog).Create()

		c.Flash.Error("Authenticate failed: %v", authUser.Error)
		return c.Redirect(c.Request.Referer())
	}

	// save login log
	loginLog := new(models.LoginLog)
	loginLog.Account = currentUserIdentidy
	loginLog.Status = "SUCCESS"
	loginLog.IPAddress = c.Request.RemoteAddr
	mgodo.New(c.MgoSession, loginLog).Create()

	c.Session["Identity"] = strings.ToLower(currentUserIdentidy)

	//save current user information
	currentUser := new(models.User)
	currentUser.Identity = currentUserIdentidy
	// currentUser.Identity = strings.ToLower(account)
	currentUser.Mail = authUser.Email
	currentUser.Avatar = authUser.Avatar
	currentUser.Name = authUser.Name
	currentUser.Depart = authUser.Depart
	currentUser.First = authUser.First
	currentUser.Last = authUser.Last

	// cache user info
	go cache.Set(c.Session.ID(), currentUser, cache.DefaultExpiryTime)

	go func(user *models.User) {
		// save to local user
		s := mgodo.NewMgoSession()
		defer s.Close()
		err := user.SaveUser(s)
		if err != nil {
			revel.AppLog.Errorf("Save user error: %v", err)
		}

	}(currentUser)

	c.Flash.Success("Welcome, %v", currentUser.Name)
	return c.Redirect(nextUrl)
}

// Logout
func (c *Auth) Logout() revel.Result {
	//delete cache which is logged in user info
	cache.Delete(c.Session.ID())
	c.Session = make(map[string]interface{})
	/**
	 * Construct a logout URI and redirect the user to end the
	 * session with Azure AD. For more information, visit:
	 * https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
	 */
	if revauthaad.AzureADTenantAuthority == "" || strings.TrimSpace(revauthaad.AzureADTenantAuthority) == "" {
		c.Flash.Error("No Azure AD tenant authority found, please contact with system administrator.")
	}
	if revauthaad.AppLogoutRedirectUrl == "" || strings.TrimSpace(revauthaad.AppLogoutRedirectUrl) == "" {
		c.Flash.Error("No application logout redirect url found, please contact with system administrator.")
	}
	logoutUri := fmt.Sprintf("%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s", revauthaad.AzureADTenantAuthority, revauthaad.AppLogoutRedirectUrl)
	c.Flash.Success("You have logged out.")
	return c.Redirect(logoutUri)
}
