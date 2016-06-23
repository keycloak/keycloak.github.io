<#assign title = "Documentation Archive">

<#include "../templates/header.ftl">
<#include "../templates/menu.ftl">

<div class="page-section">
    <div class="container">
        <h1>Documentation Archive</h1>

        <ol class="breadcrumb">
            <li><a href="documentation.html">Documentation</a></li>
            <li class="active">Archive</li>
        </ol>

        <ul>
        <#list versions as version>
            <li><a href="documentation-${version.versionShort}.html">${version.versionShort}</a></li>
        </#list>
        </ul>
    </div>
</div>

<#include "../templates/footer.ftl">