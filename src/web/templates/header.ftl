<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <title>Keycloak<#if (title)??> - ${title}</#if></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Keycloak is an open source identity and access management solution">
    <meta name="author" content="Keycloak Team">
    <meta name="keywords" content="sso,idm,openid connect,saml,kerberos,ldap">

    <link href="resources/css/bootstrap.min.css" rel="stylesheet">
    <link href="resources/css/prettify.css" rel="stylesheet">
    <link href="resources/font-awesome/css/font-awesome.min.css" rel="stylesheet">
    <link href="resources/css/keycloak.css" rel="stylesheet">
    <link href="resources/css/tabzilla.css" rel="stylesheet">

    <!--[if lt IE 9]>
    <script src="resources/js/html5shiv.min.js"></script>
    <![endif]-->

    <link rel="shortcut icon" href="resources/favicon.ico">

    <script src="resources/js/jquery-1.11.1.min.js"></script>
    <script src="resources/js/bootstrap.min.js"></script>
    <script src="resources/js/prettify.js"></script>
    <script src="resources/js/jbossorg-tabzilla.js"></script>
    <script>
        (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
                    (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
                m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
        })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

        ga('create', 'UA-79404298-1', 'auto');
        ga('send', 'pageview');

    </script>
    <script>
        var version = '${version.version}';
        function dl(category, label) {
            console.debug(category + '-' + label + '-' + version);
            ga('send', 'event', category, category + '-' + label, category + '-' + label + '-' + version);
        }
    </script>
</head>
<body onload="prettyPrint()">
<div id="wrap">

<div class="dropup">
    <a class="tabnav-closed" href="#" id="tab">Red Hat</a>
    <script>
        window.addEventListener('load', function() {
            renderTabzilla("Keycloak", "http://www.keycloak.org", true );
        }, false);
    </script>
</div>