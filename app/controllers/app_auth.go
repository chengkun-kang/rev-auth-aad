package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	revauthaad "github.com/chengkun-kang/rev-auth-aad"
	revauthaadmodels "github.com/chengkun-kang/rev-auth-aad/app/models"

	mgodo "github.com/lujiacn/mgodo"
	"github.com/revel/revel"
	"github.com/revel/revel/cache"
)

type AppAuth struct {
	*revel.Controller
	mgodo.MgoController
}

type UserProfile struct {
	Id                       string `json:"id"`
	Mail                     string `json:"mail"`
	Avatar                   string `json:"avatar"`
	Surname                  string `json:"surname"`
	JobTitle                 string `json:"jobTitle"`
	GivenName                string `json:"givenName"`
	EmployeeId               string `json:"employeeId"`
	Department               string `json:"department"`
	DisplayName              string `json:"displayName"`
	OfficeLocation           string `json:"officeLocation"`
	PostalCode               string `json:"postalCode"`
	OnPremisesSamAccountName string `json:"onPremisesSamAccountName"`
}

func SetAzureADViewArgs(c *revel.Controller) revel.Result {
	log.Println("Setting azure AD info to view args......")
	c.ViewArgs["AzureADAppClientId"] = revauthaad.AzureADAppClientId
	c.ViewArgs["AzureADGraphApiMePath"] = revauthaad.AzureADGraphApiMePath
	c.ViewArgs["AzureADAppRedirectUri"] = revauthaad.AzureADAppRedirectUri
	c.ViewArgs["AzureADApiPublicScopes"] = revauthaad.AzureADApiPublicScopes
	c.ViewArgs["AzureADTenantAuthority"] = revauthaad.AzureADTenantAuthority
	c.ViewArgs["AzureADAppPostLogoutRedirectUri"] = revauthaad.AzureADAppPostLogoutRedirectUri
	return nil
}

// Authenticate for Azure AD, called from UI and pass userinfo in callback from AAD
// For user properties in Azure AD refer: https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
func (c *AppAuth) Authenticate(identity string) revel.Result {
	log.Println("Authenticate identity:", identity)
	// direct logout if no sanofi identity passed
	if identity == "" {
		c.Flash.Error("Only sanofi employee can access, please contact the administrator for help.")
		return c.RenderTemplate("AppAuth/Logout.html")
	}

	userProfile := UserProfile{}
	loginLog := new(revauthaadmodels.LoginLog)
	currentLoginIdentifier := strings.ToLower(identity)
	err := json.Unmarshal(c.Params.JSON, &userProfile)
	if err != nil {
		log.Println("Umarshal err", err)
		loginLog.Status = "FAILURE"
		loginLog.IPAddress = c.Request.RemoteAddr
		mgodo.New(c.MgoSession, loginLog).Create()

		c.Flash.Error("Fetch user profile failed, please contact with system administrator.")
		return c.Redirect(c.Request.Referer())
	}

	loginLog.Account = currentLoginIdentifier
	loginLog.Status = "SUCCESS"
	loginLog.IPAddress = c.Request.RemoteAddr
	mgodo.New(c.MgoSession, loginLog).Create()

	c.Session["Identity"] = currentLoginIdentifier

	//save current user information
	currentUser := new(revauthaadmodels.User)
	currentUser.Identity = currentLoginIdentifier
	currentUser.Mail = userProfile.Mail
	currentUser.Avatar = userProfile.Avatar
	currentUser.Name = userProfile.DisplayName
	currentUser.Depart = userProfile.Department
	currentUser.First = userProfile.GivenName
	currentUser.Last = userProfile.Surname

	log.Println("Cache user information: ", currentUser)
	// cache user info
	go cache.Set(c.Session.ID(), currentUser, cache.DefaultExpiryTime)

	go func(user *revauthaadmodels.User) {
		// save to local user
		s := mgodo.NewMgoSession()
		defer s.Close()
		err := user.SaveUser(s)
		if err != nil {
			revel.AppLog.Errorf("Save user error: %v", err)
		}

	}(currentUser)

	return c.RenderJSON(map[string]string{"status": "success"})
}

// Logout
func (c *AppAuth) Logout() revel.Result {
	if revauthaad.AzureADTenantAuthority == "" || strings.TrimSpace(revauthaad.AzureADTenantAuthority) == "" {
		c.Flash.Error("No Azure AD tenant authority found, please contact with system administrator.")
		return c.Redirect(c.Request.Referer())
	}
	if revauthaad.AzureADAppPostLogoutRedirectUri == "" || strings.TrimSpace(revauthaad.AzureADAppPostLogoutRedirectUri) == "" {
		c.Flash.Error("No application logout redirect url found, please contact with system administrator.")
		return c.Redirect(c.Request.Referer())
	}

	//delete cache which is logged in user info
	cache.Delete(c.Session.ID())
	c.Session = make(map[string]interface{})

	/**
	 * Construct a logout URI and redirect the user to end the
	 * session with Azure AD. For more information, visit:
	 * https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
	 */
	logoutUri := fmt.Sprintf("%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s", revauthaad.AzureADTenantAuthority, revauthaad.AzureADAppPostLogoutRedirectUri)

	c.Flash.Success("You have logged out.")
	return c.Redirect(logoutUri)
}
