package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/Azure/azure-sdk-for-go/arm/keyvault"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	KeyVault "github.com/Azure/azure-sdk-for-go/dataplane/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	riviera "github.com/jen20/riviera/azure"
	"github.com/satori/uuid"
)

type ClientConfiguration struct {
	ClientId       string
	ClientSecret   string
	Environment    string
	SubscriptionId string
	TenantId       string
}

type Client struct {
	Config               ClientConfiguration
	Environment          *azure.Environment
	KeyVaultToken        *adal.ServicePrincipalToken
	ResourceManagerToken *adal.ServicePrincipalToken
}

func main() {
	log.Println("HEYO")
	config := ClientConfiguration{
		ClientId:       os.Getenv("ARM_CLIENT_ID"),
		ClientSecret:   os.Getenv("ARM_CLIENT_SECRET"),
		Environment:    os.Getenv("ARM_ENVIRONMENT"),
		SubscriptionId: os.Getenv("ARM_SUBSCRIPTION_ID"),
		TenantId:       os.Getenv("ARM_TENANT_ID"),
	}

	log.Println("Creating Azure Client..")
	client, err := getAzureClient(config)
	if err != nil {
		panic(err)
	}

	log.Println("Creating Resource Group..")
	resourceGroup, err := client.createResourceGroup("tharvey-localdev", "westeurope")
	if err != nil {
		panic(err)
	}

	log.Println("Resource Group ID: " + *resourceGroup.ID)

	log.Println("Creating Key Vault..")
	applicationId := client.Config.ClientId
	vault, err := client.createKeyVaultInResourceGroup(resourceGroup, "tharvey-keyvault", applicationId)
	if err != nil {
		panic(err)
	}

	log.Println("Vault ID: " + *vault.ID)

	log.Println("Creating Secret..")
	secret, err := client.createSecretInKeyVault(resourceGroup, vault, "rick", "morty")
	if err != nil {
		panic(err)
	}

	log.Println("Secret ID: " + *secret.ID)
}

func getAzureClient(config ClientConfiguration) (*Client, error) {
	env, err := getAzureEnvironment(config.Environment)
	if err != nil {
		return nil, err
	}

	oauthConfig, err := getAzureOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantId)
	if err != nil {
		return nil, err
	}

	resourceManagerSpt, err := adal.NewServicePrincipalToken(*oauthConfig, config.ClientId, config.ClientSecret, env.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	// also tried "https://login.windows.net/" which is returned in the `WWW-Authenticate` header
	keyVaultOauthConfig, err := getAzureOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantId)
	if err != nil {
		return nil, err
	}

	// context.AcquireToken(resource, new ClientCredential(AppClientId,AppKey));
	//keyVaultSpt, err := adal.NewServicePrincipalTokenFromManualToken(*oauthConfig, config.ClientId, "env.KeyVaultEndpoint", resourceManagerSpt.Token)
	keyVaultSpt, err := adal.NewServicePrincipalToken(*keyVaultOauthConfig, config.ClientId, config.ClientSecret, env.KeyVaultEndpoint)
	if err != nil {
		return nil, err
	}

	client := Client{
		Config:               config,
		Environment:          env,
		KeyVaultToken:        keyVaultSpt,
		ResourceManagerToken: resourceManagerSpt,
	}
	return &client, nil
}

func (c Client) createResourceGroup(resourceGroupName, location string) (*resources.Group, error) {
	client := resources.NewGroupsClientWithBaseURI(c.Environment.ResourceManagerEndpoint, c.Config.SubscriptionId)
	client.Authorizer = autorest.NewBearerAuthorizer(c.ResourceManagerToken)
	client.Sender = autorest.CreateSender(withRequestLogging())

	properties := resources.Group{
		Location: &location,
	}

	_, err := client.CreateOrUpdate(resourceGroupName, properties)
	if err != nil {
		return nil, err
	}

	group, err := client.Get(resourceGroupName)
	if err != nil {
		return nil, err
	}

	return &group, nil
}

func (c Client) createKeyVaultInResourceGroup(resourceGroup *resources.Group, name, applicationId string) (*keyvault.Vault, error) {
	client := keyvault.NewVaultsClientWithBaseURI(c.Environment.ResourceManagerEndpoint, c.Config.SubscriptionId)
	client.Authorizer = autorest.NewBearerAuthorizer(c.ResourceManagerToken)
	client.Sender = autorest.CreateSender(withRequestLogging())

	tenantId, err := uuid.FromString(c.Config.TenantId)
	if err != nil {
		return nil, err
	}

	properties := keyvault.VaultCreateOrUpdateParameters{
		Location: resourceGroup.Location,
		Properties: &keyvault.VaultProperties{
			Sku: &keyvault.Sku{
				Name:   keyvault.SkuName("Standard"),
				Family: riviera.String("A"),
			},
			AccessPolicies: &[]keyvault.AccessPolicyEntry{
				// application
				{
					TenantID: &tenantId,
					ObjectID: &applicationId,
					Permissions: &keyvault.Permissions{
						Secrets: &[]keyvault.SecretPermissions{
							keyvault.SecretPermissionsAll,
						},
					},
				},

				/*
				// user
				{
					TenantID: &tenantId,
					ObjectID: &userObjectId,
					Permissions: &keyvault.Permissions{
						Secrets: &[]keyvault.SecretPermissions{
							keyvault.SecretPermissionsAll,
						},
					},
				},
				*/
			},
			TenantID: &tenantId,
		},
	}
	_, err = client.CreateOrUpdate(*resourceGroup.Name, name, properties)
	if err != nil {
		return nil, err
	}

	vault, err := client.Get(*resourceGroup.Name, name)
	if err != nil {
		return nil, err
	}

	return &vault, nil
}

func (c Client) createSecretInKeyVault(resourceGroup *resources.Group, keyVault *keyvault.Vault, name, value string) (*KeyVault.SecretBundle, error) {
	client := KeyVault.New()
	//client.Authorizer = autorest.NewBearerAuthorizer(HardCodedToken{})
	client.Authorizer = autorest.NewBearerAuthorizer(c.KeyVaultToken)
	client.Sender = autorest.CreateSender(withRequestLogging())

	parameters := KeyVault.SecretSetParameters{
		Value: &value,
	}
	_, err := client.SetSecret(*keyVault.Properties.VaultURI, name, parameters)
	if err != nil {
		return nil, err
	}

	// the API Documentation says setting the SecretVersion field to an empty string should return the latest version, but also fails if specified
	secret, err := client.GetSecret(*keyVault.Properties.VaultURI, name, "")
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

func getAzureOAuthConfig(endpoint, tenantId string) (*adal.OAuthConfig, error) {
	oauthConfig, err := adal.NewOAuthConfig(endpoint, tenantId)
	if err != nil {
		return nil, err
	}

	// OAuthConfigForTenant returns a pointer, which can be nil.
	if oauthConfig == nil {
		return nil, fmt.Errorf("Unable to configure OAuthConfig for tenant %s", tenantId)
	}

	return oauthConfig, nil
}

func getAzureEnvironment(environment string) (*azure.Environment, error) {
	env, envErr := azure.EnvironmentFromName(environment)

	if envErr != nil {
		// try again with wrapped value to support readable values like german instead of AZUREGERMANCLOUD
		wrapped := fmt.Sprintf("AZURE%sCLOUD", environment)
		var innerErr error
		if env, innerErr = azure.EnvironmentFromName(wrapped); innerErr != nil {
			return nil, envErr
		}
	}

	return &env, nil
}

func withRequestLogging() autorest.SendDecorator {
	return func(s autorest.Sender) autorest.Sender {
		return autorest.SenderFunc(func(r *http.Request) (*http.Response, error) {
			// dump request to wire format
			if dump, err := httputil.DumpRequestOut(r, true); err == nil {
				log.Printf("[DEBUG] AzureRM Request: \n%s\n", dump)
			} else {
				// fallback to basic message
				log.Printf("[DEBUG] AzureRM Request: %s to %s\n", r.Method, r.URL)
			}

			resp, err := s.Do(r)
			if resp != nil {
				// dump response to wire format
				if dump, err := httputil.DumpResponse(resp, true); err == nil {
					log.Printf("[DEBUG] AzureRM Response for %s: \n%s\n", r.URL, dump)
				} else {
					// fallback to basic message
					log.Printf("[DEBUG] AzureRM Response: %s for %s\n", resp.Status, r.URL)
				}
			} else {
				log.Printf("[DEBUG] Request to %s completed with no response", r.URL)
			}
			return resp, err
		})
	}
}