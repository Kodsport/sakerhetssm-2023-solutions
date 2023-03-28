# URGENT
The URGENT Challenge is meant as an introduction to the Windows world, as well as Azure AD.
Since there is no real build script for this challenge, this document will describe how the challenge was composed.

## Rationale
URGENT is a challenge produced as sponsor material for Cparta Cyber Defense AB, our goal is to protect Swedish critical infrastructure. The majority of Swedish critical infrastructure interacts in one way or another with Microsoft systems, such as Windows, Windows servers, Active Directory, or hybrid joined solutions through Azure AD. In the CTF community, this important pillar of infrastructure is not fairly represented in form of challenges, often because of licensing issues. However, it is our firm belief that this knowledge and experience is imperative for the future of Swedish cyber experts. Therefore, we decided to create an introductory challenge representing a piece of these technologies.

## Intuned Devices
When intuning a device, a.k.a, connecting it to Azure Active Directory (AAD), the device recieves among other things, a PRT token.
The PRT token is used for authenticating towards AAD applications, such as the Office family of products, microsoft teams, et.c.
In machines without a TPM, this PRT token is stored directly in the memory of the lsass.exe process, thus, when reading this memory, we can extract these tokens.

## Azure Tenants
A "Tenant" in Azure, is an organization registered to Microsoft Azure. When signing in with Microsoft accounts which belongs to a tenant, the organization can ensure certain rules on the device. *However*, these rules are checked on the device, and as such can be spoofed or falsified. 

## Microsoft Graph API
The Microsoft Graph API is the API for essentially all azure registrations/applications. With this API, you can fetch outlook messages, sharepoint files, et.c.
In order to communicate with the API, you need a JWT token which gives you authorization for the "client" (application) with the correct roles, depending on what you want to do.
For example, if you want to fetch outlook messages, you would need a JWT token which authorizes for the outlook mobile application (UUID: 27922004-5251-4030-b22d-91ecd9a37ea4).

With the "scope" Mail.Read, further information regarding this can be found over at [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0&tabs=http).
Another good read is [Family of Client IDs](https://github.com/secureworks/family-of-client-ids-research).

## Building the challenge
You can register a 90-day trial development tenant for free at Azure Development Program. Set up a Windows VM, sign in with one of the users inside this tenant.
After this, there will exist a PRT token within the lsass.exe process running in the VM. You can then dump the memory of lsass, using either task manager, or some other tool that generates minidumps.

## Bonus Challenges
For those who want to improve their Windows knowledge, following are some project ideas / challenges
* Dumping lsass.exe with MiniDumpWriteDump
  1. Easy: Dump directly to file
  2. Medium: Dump an encrypted version to file, never let the minidump touch the filesystem directly.
  3. Hard: Don't get caught by Microsoft Defender
  4. Impossible: Integrate this with a C2 beacon without being detected by any Antivirus (AV) 
* Create a parser for the minidump format (mimikatz but better)
* Try escaping the Azure CAP rules [Conditional Access](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)
