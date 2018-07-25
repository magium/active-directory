
# Magium Active Directory Integration

*For stupid-easy PHP integration with Azure Active Directory*.

This is a simple library that uses the `league/oauth2-client` to provide OAuth2 based integration with Active Directory.  Out of the box it is configured to work with Active Directory on Azure but, though I haven't tested it, you can provide a different configuration object to the primary adapter and you should be able to authenticate against any Active Directory implementation as long as it has OAuth2 connectivity.

There are two purposes (well, three) for library.

1. Provide sub-5 minute installation and integration times for any PHP-based application
2. Provide a launching pad for other third-party integrations to Microsoft Azure Active Directory, such as Magento, Drupal, Oro, or whatever.
3. (provide libraries that use other Magium libraries so people can see how awesome all the Magium stuff is)

First, watch the [installation video on YouTube](https://www.youtube.com/watch?v=9FupzL2XsqA).  It shows you how to create an application in Azure Active Directory.  A big part of the installation is going to the Microsoft Application Console at [https://apps.dev.microsoft.com](https://apps.dev.microsoft.com).  That is where you are going to get all of your authentication keys and such.

**Note** Azure will not redirect from a secure URL (i.e. their login page) to an unsecure page (i.e. your page).  No HTTPS to HTTP in other words.  In yet other words, if you use Azure you will need to also use HTTPS.  Though there are worse things in the world... like *not* using HTTPS.

## Basic Usage

Anywhere in your application that requires authentication you can provide this code (properly architected, not cut and paste, in other words):

``` php
$ad = new \Magium\ActiveDirectory\ActiveDirectory(
    $configuration, // shown later
    $psr7CompatibleRequest
);

$entity = $ad->authenticate();
```

The `authenticate()` method will do 1 of 3 things.

1. Check the session and see that the user is not logged in, forwarding that person to their Azure Active Directory login page
2. Validate return data from Active Directory
3. Simply return the `Entity` object if the person is already logged in.

If you want to log out all you do is:

``` php
$ad->forget();
```

Not that this only purges the AD entity from the session, it does not do any other session cleanup for your application.

Clearly this library is not intended to be your only means of session management, though, for simple applications, you could use it that way.  Most likely you will want to take the data retrieved from AD and link it to a local account.  The `Entity` class has 3 defined getters to help you do this mapping:

``` php
echo $entity->getName() . '<Br />'; // The user's name
echo $entity->getOid() . '<Br />'; //The user's AD object ID, useful for mapping to a local user obhect
echo $entity->getPreferredUsername() . '<Br />'; // The user's username, usually an email address.
```

## Installation

```
composer require magium/active-directory
```

Done.

## Configuration

This is a little more in-depth, but it shouldn't be overly complex.

The base configuration is managed by the [Magium Configuration Manager](https://www.github.com/magium/configuration-manager), out of the box.  But, that said, the MCM has a really simple mechanism that allows you to not use the underlying plumbing.  I believe that the underlying plumbing will eventually make application management easier, but I'm not going to force it on you.

### Configuration using the Magium Configuration Manager

The configuration manager provides the means to manage and deploy settings at runtime in both a CLI and (eventually) a web-based interface.  If you are using the configuration manager you need to get an instance of the configuration factory, which provides an instance of the manager, which provides the configuration object.  The `ActiveDirectory` adapter requires that configuration object.

``` php
// Convert to PSR7 request object
$request = \Zend\Psr7Bridge\Psr7ServerRequest::fromZend(
    new \Zend\Http\PhpEnvironment\Request()
);

$factory = new \Magium\Configuration\MagiumConfigurationFactory();
$manager = $factory->getManager();
$configuration = $manager->getConfiguration();

$adapter = new \Magium\ActiveDirectory\ActiveDirectory($configuration, $request);

$entity = $adapter->authenticate();
```

First, in your application root directory run `vendor/bin/magium magium:configuration:list-keys`.  This is done after you have configured the MCM according to its instructions in the GitHub link.  You will see output like this:

```
Valid configuration keys
authentication/ad/enabled (default: 0)
        (Is the Magium Active Directory integration enabled?)

authentication/ad/client_id
        (You need to configure an application in Active Directory and enter its ID here)

authentication/ad/client_secret
        (When you created an application in Active Directory you should have received a one-time use key.  Enter that here.  )

authentication/ad/directory (default: common)
        (Provide a directory ID if you are using your own Azure instance instead of Microsoft's global database.  The directory ID is usually found under the directory properties.)

authentication/ad/return_url
        (This is the URL you want Active Directory to redirect back to after authentication.)

authentication/ad/remap_https (default: 1)
        (Should the system remap HTTP-based URLs to HTTPS.  Azure Active Directory generally will not redirect to a non-secure URL.  Enabling this setting protects against that.)
```

You will need to provide those two values for the configuration:

```
vendor/bin/magium magium:configuration:set magium/ad/client_id '<my client id>'
Set magium/ad/client_id to <my client id> (context: default)
Don't forget to rebuild your configuration cache with magium:configuration:build

vendor/bin/magium magium:configuration:set magium/ad/client_secret '<my client secret>'
Set magium/ad/client_secret to <my client secret> (context: default)
Don't forget to rebuild your configuration cache with magium:configuration:build

vendor/bin/magium magium:configuration:build
Building context: default
Building context: production
Building context: development
```

And you should be good to go.

**Achtung!!!**  The defaults for the adapter will allow *anyone* with a Microsoft ID to access your system, kind of like allowing any Twitter user access your system if they have a valid Twitter account.  If you are looking to authenticate against your own Active Directory instance make sure you provide the Directory ID for the directory you will to validate against.  All of the following examples include the directory configuration key, whose default is "common".  Make sure you are authenticating not just against the correct application with the client_id, but also the correct directory with the directory key.

### Configuration using PHP Arrays

Now, I know the MCM is new and you probably aren't using it.  That's why I provided a way for you configure the adapter without using the full-blown MCM.  You can use the `Magium\Configuration\Config\Repository\ArrayConfigurationRepository` class to provide a raw array that will be mapped to the two configuration settings `magium/ad/client_id` and `magium/ad/client_secret`

``` php
session_start();

$config = [
    'authentication' => [
        'ad' => [
            'client_id' => '<my client id>',
            'client_secret' => '<my client secret>',
            'enabled' => 'yes',
            'directory' => '<common or directory ID>'
        ]
    ]
];

$request = new \Zend\Http\PhpEnvironment\Request();

$ad = new \Magium\ActiveDirectory\ActiveDirectory(
    new \Magium\Configuration\Config\Repository\ArrayConfigurationRepository($config),
    Zend\Psr7Bridge\Psr7ServerRequest::fromZend(new \Zend\Http\PhpEnvironment\Request())
);

$entity = $ad->authenticate();

echo $entity->getName() . '<Br />';
echo $entity->getOid() . '<Br />';
echo $entity->getPreferredUsername() . '<Br />';
```

### Configuration using YAML

Pretty much the same, but rather than using the `ArrayConfigurationRepository` you will use the `YamlConfigurationRepository`.  It's pretty similar:

``` php
$yaml = <<<YAML
authentication:
    ad:
        client_id: <value>
        client_secret: <value>
        enabled: yes
        directory: <common or directory ID>
YAML;

$obj = new YamlConfigurationRepository(trim($yaml));
$ad = new \Magium\ActiveDirectory\ActiveDirectory(
    $obj, $request
);

$entity = $ad->authenticate();
```

### Configuration using JSON

Pretty much the same, but rather than using the `YamlConfigurationRepository` you will use the `JsonConfigurationRepository`.  It's pretty similar:

``` php
 $json = <<<JSON
        {
            "authentication": {
                "ad": {
                    "client_id": "<value>",
                    "client_secret": "<value>",
                    "enabled": "yes",
                    "directory": "<common or directory ID>"
                }
            }
        }
JSON;
        $obj = new JsonConfigurationRepository(trim($json));
$ad = new \Magium\ActiveDirectory\ActiveDirectory(
    $obj, $request
);

$entity = $ad->authenticate();
```

### Configuration using INI Files

Pretty much the same, but rather than using the `JsonConfigurationRepository` you will use the `IniConfigurationRepository`.  It's pretty similar:

``` php
$ini = <<<INI
[authentication]
ad[client_id] = <value>
ad[client_srcret] = <value>
ad[enabled] = yes
ad[directory] = <common or directory ID>
INI;

$obj = new IniConfigurationRepository(trim($ini));
$ad = new \Magium\ActiveDirectory\ActiveDirectory(
    $obj, $request
);

$entity = $ad->authenticate();
```
