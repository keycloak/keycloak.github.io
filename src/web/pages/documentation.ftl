<#assign title = "Documentation">

<#include "../templates/header.ftl">
<#include "../templates/menu.ftl">

<div class="page-section">
    <div class="container">
        <h1>Documentation - ${version.versionShorter}</h1>

        <p>
        <#if !version.final>
            This is a <b>release candidate</b>. The latest final release is <a href="documentation-${versions[1].versionShort}.html">${versions[1].versionShort}</a>.
        </#if>
            For older releases go <a href="documentation-archive.html">here</a>.
        </p>

        <#include "../templates/documentation-${version.documentationTemplate}.ftl">
    </div>
</div>

<#include "../templates/footer.ftl">