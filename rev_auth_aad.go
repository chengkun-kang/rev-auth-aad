package revauthaad

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/chengkun-kang/rev-auth-aad/app/models"
	"github.com/chengkun-kang/rev-auth-aad/cache"
	"github.com/chengkun-kang/rev-auth-aad/utils"
	"github.com/lujiacn/mgodo"

	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azauthlibgocred "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	azauthlibgopublic "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	httpclient "github.com/chengkun-kang/rev-auth-aad/lib/http-client"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphsdkme "github.com/microsoftgraph/msgraph-sdk-go/me"
	msgraphsdkusers "github.com/microsoftgraph/msgraph-sdk-go/users"

	"github.com/revel/revel"
)

var (
	aadAppClientId     string
	aadAppClientSecret string

	aadTenantId               = ""
	aadTenantAuthority        = ""
	aadAccountPrimaryDomain   = ""
	aadCloudInstance          = "https://login.microsoftonline.com"
	aadApiUsersPath           = "https://graph.microsoft.com/v1.0/users"
	aadAppApiPublicScopes     = []string{"User.Read"}
	aadAppApiCredentialScopes = []string{"https://graph.microsoft.com/.default"}

	appLogoutRedirectUrl = "/login"
)

type AuthReply struct {
	IsAuthenticated bool
	Error           string
	Account         string
	Name            string
	First           string
	Last            string
	Email           string
	Depart          string
	Avatar          string
}

type QueryReply struct {
	NotExist bool
	Error    string
	Account  string
	Name     string
	First    string
	Last     string
	Email    string
	Depart   string
	Avatar   string
}

// InitAAD reading AAD configuration
func InitAAD() {
	var found bool
	if aadTenantId, found = revel.Config.String("aad.tenant.id"); !found {
		panic("aad.tenant.id not defined in revel app.conf file")
	} else if aadTenantId == "" || strings.TrimSpace(aadTenantId) == "" {
		panic("aad.tenant.id cannot be empty before authentication")
	}
	if tempCloudInstance, found := revel.Config.String("aad.cloud.instance"); found &&
		tempCloudInstance != "" && strings.TrimSpace(tempCloudInstance) != "" {
		aadCloudInstance = tempCloudInstance
	}
	aadTenantAuthority = fmt.Sprintf("%s/%s", utils.TrimSuffix(aadCloudInstance, "/"), aadTenantId)
	if tempLogoutRedirectUrl, found := revel.Config.String("app.logout.redirect.url"); found &&
		tempLogoutRedirectUrl != "" && strings.TrimSpace(tempLogoutRedirectUrl) != "" {
		appLogoutRedirectUrl = tempLogoutRedirectUrl
	}
	if accountDomain, found := revel.Config.String("aad.account.primary.domain"); found &&
		accountDomain != "" && strings.TrimSpace(accountDomain) != "" {
		aadAccountPrimaryDomain = accountDomain
	}
	if tempAADApiUsersPath, found := revel.Config.String("aad.api.users.path"); found &&
		tempAADApiUsersPath != "" && strings.TrimSpace(tempAADApiUsersPath) != "" {
		aadApiUsersPath = tempAADApiUsersPath
	}
	if aadAppClientId, found = revel.Config.String("aad.app.client.id"); !found {
		panic("aad.app.client.id not defined in revel app.conf file")
	} else if aadAppClientId == "" || strings.TrimSpace(aadAppClientId) == "" {
		panic("aad.app.client.id cannot be empty before authentication")
	}
	if aadAppClientSecret, found = revel.Config.String("aad.app.client.secret"); !found {
		panic("aad.app.client.secret not defined in revel app.conf file")
	} else if aadAppClientSecret == "" || strings.TrimSpace(aadAppClientSecret) == "" {
		panic("aad.app.client.secret cannot be empty before authentication")
	}
	if apiPublicScopesStr, found := revel.Config.String("aad.api.public.scopes"); found {
		if apiPublicScopesStr != "" && strings.TrimSpace(apiPublicScopesStr) != "" {
			aadAppApiPublicScopes = utils.RemoveBlankStrings(strings.Split(apiPublicScopesStr, ","))
			if len(aadAppApiPublicScopes) == 0 {
				panic("aad.api.public.scopes cannot be empty items before fetch authentication token")
			}
		}
	}

	if apiCredentialScopesStr, found := revel.Config.String("aad.api.credential.scopes"); found {
		if apiCredentialScopesStr != "" && strings.TrimSpace(apiCredentialScopesStr) != "" {
			aadAppApiCredentialScopes = utils.RemoveBlankStrings(strings.Split(apiCredentialScopesStr, ","))
			if len(aadAppApiCredentialScopes) == 0 {
				panic("aad.api.credential.scopes cannot be empty items before fetch authentication token")
			}
		}
	}
}

// account should be the user's email address.
// https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc
// The application should enable public clients https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc
// Ask admin to open this configuration in application/Authenticatioin/Advanced Settings/Allow public client flows

func InitPublicClient(account, password string) (*msgraphsdk.GraphServiceClient, error) {
	tempAccount := account
	isMail := utils.MAIL_REGEX.MatchString(tempAccount)
	// construct the username to principal username
	if !isMail && aadAccountPrimaryDomain != "" && strings.TrimSpace(aadAccountPrimaryDomain) != "" {
		tempAccount = fmt.Sprintf(`%s@%s`, tempAccount, aadAccountPrimaryDomain)
	}

	log.Printf("Start initializing Graph service client on %s\n", time.Now())
	cred, err := azidentity.NewUsernamePasswordCredential(
		aadTenantId,
		aadAppClientId,
		account,
		password,
		nil,
	)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create client with username password credentials: %v", err))
	}

	log.Printf("Start to authenticate for user: %s...", tempAccount)
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, aadAppApiPublicScopes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create graph client with credentials: %v", err))
	}

	return client, nil
}

func InitCredentialClient() (*msgraphsdk.GraphServiceClient, error) {
	cred, err := azidentity.NewClientSecretCredential(
		aadTenantId,
		aadAppClientId,
		aadAppClientSecret,
		nil,
	)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create credentials: %v", err))
	}

	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, aadAppApiCredentialScopes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create client with client credentials: %v", err))
	}

	return client, nil
}

// Authenticate do auth and return Auth object including user information and lognin success or not
// Required Delegated Permission: User.Read, and Grant admin consent as this is a Daemon web api.
// account could be the pricipal user name in AAD or mail of login user
func AuthenticatePublicClient(account, password string) *AuthReply {
	authReply := &AuthReply{}
	// below Call will return error when using credentials client
	msGraphClient, err := InitPublicClient(account, password)
	if err != nil {
		log.Println("Init client failed: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	requestParameters := &msgraphsdkme.MeRequestBuilderGetQueryParameters{
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId"
		Select: []string{"id", "displayName", "givenName", "surname", "mail", "department", "employeeId"},
	}
	configuration := &msgraphsdkme.MeRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}
	// retrieve the sign in user information from AAD
	currentUserReponse, err := msGraphClient.Me().Get(context.Background(), configuration)
	if err != nil || currentUserReponse.GetId() == nil {
		log.Println("Retrieving user failed with error: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	authReply.IsAuthenticated = true
	if currentUserReponse.GetEmployeeId() != nil {
		log.Printf("Authenticated user employeeID: %s\n", *currentUserReponse.GetEmployeeId())
		authReply.Account = *currentUserReponse.GetEmployeeId()
	}
	if currentUserReponse.GetDisplayName() != nil {
		authReply.Name = *currentUserReponse.GetDisplayName()
	}
	if currentUserReponse.GetGivenName() != nil {
		authReply.First = *currentUserReponse.GetGivenName()
	}
	if currentUserReponse.GetSurname() != nil {
		authReply.Last = *currentUserReponse.GetSurname()
	}
	if currentUserReponse.GetMail() != nil {
		authReply.Email = *currentUserReponse.GetMail()
	}
	if currentUserReponse.GetDepartment() != nil {
		authReply.Depart = *currentUserReponse.GetDepartment()
	}
	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		authReply.Avatar = QueryUserPhotoById(*currentUserReponse.GetId(), token)
	}
	return authReply
}

func AuthenticateByClientCredentials(account string) *AuthReply {
	authReply := &AuthReply{}
	tempAccount := account
	isMail := utils.MAIL_REGEX.MatchString(tempAccount)
	// construct the username to principal username
	if !isMail && aadAccountPrimaryDomain != "" && strings.TrimSpace(aadAccountPrimaryDomain) != "" {
		tempAccount = fmt.Sprintf(`%s@%s`, tempAccount, aadAccountPrimaryDomain)
	}

	msGraphClient, err := InitCredentialClient()
	if err != nil {
		log.Println("Retrieving user failed with error: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	requestParameters := &msgraphsdkusers.UserItemRequestBuilderGetQueryParameters{
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId"
		Select: []string{"id", "displayName", "givenName", "surname", "mail", "department", "employeeId"},
	}
	configuration := &msgraphsdkusers.UserItemRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}
	// below Call will return error when using credentials client
	currentUserReponse, err := msGraphClient.UsersById(tempAccount).Get(context.Background(), configuration)
	if err != nil || currentUserReponse.GetId() == nil {
		log.Println("Retrieving user failed: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	authReply.IsAuthenticated = true
	if currentUserReponse.GetEmployeeId() != nil {
		log.Printf("Authenticated user employeeID: %s\n", *currentUserReponse.GetEmployeeId())
		authReply.Account = *currentUserReponse.GetEmployeeId()
	}
	if currentUserReponse.GetDisplayName() != nil {
		authReply.Name = *currentUserReponse.GetDisplayName()
	}
	if currentUserReponse.GetGivenName() != nil {
		authReply.First = *currentUserReponse.GetGivenName()
	}
	if currentUserReponse.GetSurname() != nil {
		authReply.Last = *currentUserReponse.GetSurname()
	}
	if currentUserReponse.GetMail() != nil {
		authReply.Email = *currentUserReponse.GetMail()
	}
	if currentUserReponse.GetDepartment() != nil {
		authReply.Depart = *currentUserReponse.GetDepartment()
	}
	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		authReply.Avatar = QueryUserPhotoById(*currentUserReponse.GetId(), token)
	}
	return authReply
}

func AcquirePublicToken(account, password string) (string, error) {
	var cacheAccessor = &cache.TokenCache{File: "./cache/serialized_cache.json"}

	log.Println("Start to fetch access token from AAD by account and password...")
	app, err := azauthlibgopublic.New(aadAppClientId, azauthlibgopublic.WithCache(cacheAccessor), azauthlibgopublic.WithAuthority(aadTenantAuthority))
	if err != nil {
		return "", err
	}

	// look in the cache to see if the account to use has been cached
	var userAccount azauthlibgopublic.Account
	accounts := app.Accounts()
	for _, accountItem := range accounts {
		if accountItem.PreferredUsername == account {
			userAccount = accountItem
		}
	}
	// found a cached account, now see if an applicable token has been cached
	// NOTE: this API conflates error states, i.e. err is non-nil if an applicable token isn't
	//       cached or if something goes wrong (making the HTTP request, unmarshalling, etc).
	result, err := app.AcquireTokenSilent(
		context.Background(),
		aadAppApiPublicScopes,
		azauthlibgopublic.WithSilentAccount(userAccount),
	)
	if err != nil {
		// either there's no applicable token in the cache or something failed
		log.Println(err)
		// either there was no cached account/token or the call to AcquireTokenSilent() failed
		// make a new request to AAD
		result, err = app.AcquireTokenByUsernamePassword(
			context.Background(),
			aadAppApiPublicScopes,
			account,
			password,
		)
		if err != nil {
			return "", err
		}
		fmt.Println("New acquired token " + result.AccessToken)
		return result.AccessToken, nil
	}
	fmt.Println("New acquired token " + result.AccessToken)
	return result.AccessToken, nil
}

func AcquireCredentialToken() (string, error) {
	var cacheAccessor = &cache.TokenCache{File: "./cache/serialized_cache.json"}

	cred, err := azauthlibgocred.NewCredFromSecret(aadAppClientSecret)
	if err != nil {
		return "", err
	}

	log.Println("Start to fetch access token from AAD...")
	client, err := azauthlibgocred.New(aadAppClientId, cred, azauthlibgocred.WithAuthority(aadTenantAuthority), azauthlibgocred.WithAccessor(cacheAccessor))
	if err != nil {
		return "", err
	}
	result, err := client.AcquireTokenSilent(context.Background(), aadAppApiCredentialScopes)
	if err != nil {
		result, err = client.AcquireTokenByCredential(context.Background(), aadAppApiCredentialScopes)
		if err != nil {
			return "", err
		}
		fmt.Println("New acquired token with client credentials: " + result.AccessToken)
		return result.AccessToken, nil
	}
	fmt.Println("New acquired silent token with client credentials: " + result.AccessToken)
	return result.AccessToken, nil
}

func Query(userIdentity string) *QueryReply {
	if userIdentity == "" || strings.TrimSpace(userIdentity) == "" {
		return &QueryReply{Error: fmt.Sprintf("Invalid user identity input, please provide a valid user identity.")}
	}
	queryReply := &QueryReply{}
	msGraphClient, err := InitCredentialClient()
	if err != nil {
		return &QueryReply{Error: fmt.Sprintf("Init Graph Service client failed with error: %v", err)}
	}

	requestCount := true
	requestFilter := url.QueryEscape(fmt.Sprintf("employeeId eq '%s'", userIdentity))
	requestParameters := &msgraphsdkusers.UsersRequestBuilderGetQueryParameters{
		Count:  &requestCount,
		Filter: &requestFilter,
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId"
		Select: []string{"id", "displayName", "givenName", "surname", "mail", "department", "employeeId"},
	}
	configuration := &msgraphsdkusers.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}

	log.Printf("Querying user info for: %s...", userIdentity)
	usersResponse, err := msGraphClient.Users().Get(context.Background(), configuration)
	if err != nil {
		return &QueryReply{Error: fmt.Sprintf("Querying user info for: %s failed with error: %v", userIdentity, err)}
	}

	usersResponseValue := usersResponse.GetValue()
	if len(usersResponseValue) == 0 {
		log.Printf("User: %s not found", userIdentity)
		queryReply.NotExist = true
		queryReply.Error = fmt.Sprintf("Account not exist with email %s!", userIdentity)
		return queryReply
	}

	if usersResponseValue[0].GetEmployeeId() != nil {
		queryReply.Account = *usersResponseValue[0].GetEmployeeId()
	}

	if queryReply.Account == "" || usersResponseValue[0].GetId() == nil {
		queryReply.Error = fmt.Sprintf("Account not exist with email %s!", userIdentity)
		queryReply.NotExist = true
		return queryReply
	}

	if usersResponseValue[0].GetDisplayName() != nil {
		queryReply.Name = *usersResponseValue[0].GetDisplayName()
	}
	if usersResponseValue[0].GetGivenName() != nil {
		queryReply.First = *usersResponseValue[0].GetGivenName()
	}
	if usersResponseValue[0].GetSurname() != nil {
		queryReply.Last = *usersResponseValue[0].GetSurname()
	}
	if usersResponseValue[0].GetMail() != nil {
		queryReply.Email = *usersResponseValue[0].GetMail()
	}
	if usersResponseValue[0].GetDepartment() != nil {
		queryReply.Depart = *usersResponseValue[0].GetDepartment()
	}

	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		queryReply.Avatar = QueryUserPhotoById(*usersResponseValue[0].GetId(), token)
	}

	return queryReply
}

func QueryMail(emailAddress string) *QueryReply {
	isMail := utils.MAIL_REGEX.MatchString(emailAddress)
	// construct the username to principal username
	if !isMail {
		return &QueryReply{Error: fmt.Sprintf("Invalid email address, please provide a valid email address.")}
	}
	queryReply := &QueryReply{}
	msGraphClient, err := InitCredentialClient()
	if err != nil {
		return &QueryReply{Error: fmt.Sprintf("Init Graph Service client failed with error: %v", err)}
	}

	requestCount := true
	requestFilter := url.QueryEscape(fmt.Sprintf("mail eq '%s'", emailAddress))
	requestParameters := &msgraphsdkusers.UsersRequestBuilderGetQueryParameters{
		Count:  &requestCount,
		Filter: &requestFilter,
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId"
		Select: []string{"id", "displayName", "givenName", "surname", "mail", "department", "employeeId"},
	}
	configuration := &msgraphsdkusers.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}

	log.Printf("Querying user info for: %s...", emailAddress)
	usersResponse, err := msGraphClient.Users().Get(context.Background(), configuration)
	if err != nil {
		return &QueryReply{Error: fmt.Sprintf("Querying user info for: %s failed with error: %v", emailAddress, err)}
	}

	usersResponseValue := usersResponse.GetValue()
	if len(usersResponseValue) == 0 {
		log.Printf("User: %s not found", emailAddress)
		queryReply.NotExist = true
		queryReply.Error = fmt.Sprintf("Account not exist with email %s!", emailAddress)
		return queryReply
	}

	if usersResponseValue[0].GetEmployeeId() != nil {
		queryReply.Account = *usersResponseValue[0].GetEmployeeId()
	}

	if queryReply.Account == "" || usersResponseValue[0].GetId() == nil {
		queryReply.Error = fmt.Sprintf("Account not exist with email %s!", emailAddress)
		queryReply.NotExist = true
		return queryReply
	}

	if usersResponseValue[0].GetDisplayName() != nil {
		queryReply.Name = *usersResponseValue[0].GetDisplayName()
	}
	if usersResponseValue[0].GetGivenName() != nil {
		queryReply.First = *usersResponseValue[0].GetGivenName()
	}
	if usersResponseValue[0].GetSurname() != nil {
		queryReply.Last = *usersResponseValue[0].GetSurname()
	}
	if usersResponseValue[0].GetMail() != nil {
		queryReply.Email = *usersResponseValue[0].GetMail()
	}
	if usersResponseValue[0].GetDepartment() != nil {
		queryReply.Depart = *usersResponseValue[0].GetDepartment()
	}

	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		queryReply.Avatar = QueryUserPhotoById(*usersResponseValue[0].GetId(), token)
	}

	return queryReply
}

func QueryMailAndSave(email string) (*models.User, error) {
	authUser := QueryMail(email)

	if authUser.Error != "" && authUser.Error != "<nil>" {
		return nil, fmt.Errorf(authUser.Error)
	}
	if authUser.NotExist {
		return nil, fmt.Errorf("User not exist")
	}

	user := new(models.User)
	user.Identity = strings.ToLower(authUser.Account)
	user.Mail = authUser.Email
	user.Avatar = authUser.Avatar
	user.Name = authUser.Name
	user.Depart = authUser.Depart
	s := mgodo.NewMgoSession()
	defer s.Close()
	user.SaveUser(s)
	return user, nil
}

func QueryAndSave(account string) (*models.User, error) {
	authUser := Query(account)

	if authUser.Error != "" && authUser.Error != "<nil>" {
		return nil, fmt.Errorf(authUser.Error)
	}
	if authUser.NotExist {
		return nil, fmt.Errorf("User not exist")
	}

	user := new(models.User)
	user.Identity = strings.ToLower(account)
	user.Mail = authUser.Email
	user.Avatar = authUser.Avatar
	user.Name = authUser.Name
	user.Depart = authUser.Depart
	s := mgodo.NewMgoSession()
	defer s.Close()
	user.SaveUser(s)
	return user, nil
}

func QueryUserPhotoById(userId, token string) string {
	if userId == "" || token == "" {
		return ""
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	queryUrl := utils.TrimSuffix(aadApiUsersPath, "/") + fmt.Sprintf("/%s/photo/$value", userId)
	data, err := httpclient.GetJson(queryUrl, "", headers)
	if err != nil {
		log.Printf("Query user photo failed with error: %v", err)
		return ""
	}

	log.Println("Fetch user photo successfully")
	return base64.StdEncoding.EncodeToString(data)
}

func QueryUserPhotoByName(username, token string) string {
	if username == "" || token == "" {
		return ""
	}

	principalName := username
	isMail := utils.MAIL_REGEX.MatchString(username)
	if !isMail && aadAccountPrimaryDomain != "" && strings.TrimSpace(aadAccountPrimaryDomain) != "" {
		principalName = fmt.Sprintf(`%s@%s`, principalName, aadAccountPrimaryDomain)
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	queryUrl := utils.TrimSuffix(aadApiUsersPath, "/") + fmt.Sprintf("/%s/photo/$value", username)
	data, err := httpclient.GetJson(queryUrl, "", headers)
	if err != nil {
		log.Printf("Query user photo failed with error: %v", err)
		return ""
	}

	log.Println("Fetch user photo successfully")
	return base64.StdEncoding.EncodeToString(data)
}
