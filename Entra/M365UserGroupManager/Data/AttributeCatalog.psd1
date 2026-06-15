@{
    # =====================================================================================
    #  Attribute catalog  --  the single source of truth for the whole tool.
    #
    #  The Settings dialog lists every attribute here as a checkbox; the dynamic form renders
    #  each *enabled* attribute as the control implied by its Input type. Add / relabel /
    #  reorder attributes here and both the Settings list and the form update automatically.
    #
    #  Per-attribute keys:
    #    Name        Graph property name (camelCase), used verbatim in $select and the
    #                create/update payload. For extension attributes it's extensionAttributeN
    #                (nested under onPremisesExtensionAttributes by the write path).
    #    Label       Field label + Settings checkbox text.
    #    Input       Control to render. One of:
    #                  Text       single-line TextBox
    #                  Multi      multi-line TextBox, one value per line (string collection)
    #                  Bool       CheckBox (two-state; the dirty-diff baseline handles "unchanged" so an
    #                             untouched box is simply not sent on Edit)
    #                  Choice     ComboBox (DropDownList). Values from Choices or ChoiceSource.
    #                  Date       DateTimePicker with a "set?" checkbox (nullable)
    #                  Person     search-and-pick picker (see Multi / TargetType)
    #                  Password   password + force-change controls (create) / reset panel (edit)
    #                  License    SKU assign/remove list
    #                  ExtAttr    Exchange extensionAttribute1-15 (cloud-only writable)
    #                  GroupType  Security vs Microsoft 365 radio (create only; locked on edit)
    #                  Upn        sign-in local-part TextBox + verified-domain dropdown -> local@domain
    #                  ReadOnly   display-only (never written)
    #    Writable    $true if the tool ever sends this on create/update.
    #    Required    $true if it must be supplied when creating a NEW object (marked with a bold *).
    #    RequiredForCreate  like Required for submit validation (must be non-empty to create), but NOT
    #                marked with * because it auto-generates from the name (displayName/alias/UPN).
    #                Such fields are also always shown when creating, regardless of Settings.
    #    ShowOnNew   $true to include this field in the curated NEW (create) form. New mode shows the
    #                ShowOnNew set PLUS all Required/RequiredForCreate fields -- a focused create form
    #                (e.g. a new hire). EDIT mode instead shows the Settings-enabled set, so you create
    #                with the essentials and then complete the rest after the auto-switch to Edit.
    #    DefaultShow $true to enable the field by default in the EDIT view (until the user changes Settings).
    #    Choices     literal value list for Input=Choice.
    #    ChoiceSource named dynamic list for Input=Choice: 'Country' (ISO 3166-1 alpha-2).
    #    Multi       Input=Person: $true = pick many, $false = pick one.
    #    TargetType  Input=Person: 'User' | 'Group' | 'Any' (what the picker searches).
    #    MaxLength   optional length cap mirrored onto the TextBox.
    #    Help        optional tooltip.
    #    Authority   hybrid edit routing: where this field is mastered when the loaded object is
    #                directory-SYNCED from on-prem AD. 'Cloud' = stays cloud-editable even for a
    #                synced object (e.g. licenses, password w/ SSPR writeback, usageLocation, userType).
    #                Omitted => defaults to 'OnPrem' for writable fields (on-prem-mastered: shown
    #                read-only / routed to AD when the object is synced) and 'ReadOnly' for
    #                Input=ReadOnly. For a CLOUD-ONLY object every field is editable as normal,
    #                regardless of Authority. Resolved by Private/HybridDetection.ps1.
    # =====================================================================================

    User = @(
        @{
            Name = 'Identity & Sign-in'
            Attributes = @(
                @{ Name = 'userPrincipalName'; Label = 'User Principal Name'; Input = 'Upn';      Writable = $true;  Required = $false; RequiredForCreate = $true; DefaultShow = $true;  Help = 'sign-in name; local part auto-fills from the name, domain is a verified tenant domain' }
                @{ Name = 'mailNickname';      Label = 'Mail Nickname (alias)'; Input = 'Text';    Writable = $true;  Required = $false; RequiredForCreate = $true; DefaultShow = $true;  MaxLength = 64; Help = 'auto-fills as first.last from the name; no spaces; ASCII only' }
                @{ Name = 'id';                Label = 'Object ID';           Input = 'ReadOnly'; Writable = $false; Required = $false; DefaultShow = $false }
                @{ Name = 'mail';              Label = 'Primary Email';       Input = 'ReadOnly'; Writable = $false; Required = $false; DefaultShow = $true;  Help = 'managed in Exchange; not writable via Graph' }
                @{ Name = 'proxyAddresses';    Label = 'Proxy Addresses';     Input = 'ReadOnly'; Writable = $false; Required = $false; DefaultShow = $false; Help = 'read-only in Graph; recalculated from the primary email' }
            )
        }
        @{
            Name = 'Name'
            Attributes = @(
                @{ Name = 'displayName'; Label = 'Display Name'; Input = 'Text'; Writable = $true; Required = $false; RequiredForCreate = $true; DefaultShow = $true; MaxLength = 256; Help = 'auto-fills as "First Last" from the name fields' }
                @{ Name = 'givenName';   Label = 'First Name';   Input = 'Text'; Writable = $true; Required = $true;  DefaultShow = $true; Help = 'drives the auto-generated display name, alias, and sign-in name' }
                @{ Name = 'surname';     Label = 'Last Name';    Input = 'Text'; Writable = $true; Required = $true;  DefaultShow = $true; Help = 'drives the auto-generated display name, alias, and sign-in name' }
            )
        }
        @{
            Name = 'Account'
            Attributes = @(
                @{ Name = 'accountEnabled'; Label = 'Account Enabled';        Input = 'Bool';     Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $true; Help = 'defaults to enabled; uncheck to create a disabled account' }
                @{ Name = 'passwordProfile';Label = 'Password';               Input = 'Password'; Writable = $true; Required = $true;  DefaultShow = $true;  Help = 'for a synced user the reset is applied on-premises in AD; cloud-only users reset in the cloud (Authority defaults to OnPrem)' }
                @{ Name = 'usageLocation';  Label = 'Usage Location';         Input = 'Choice';   Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $true;  Authority = 'Cloud'; ChoiceSource = 'Country'; Help = 'two-letter country code; required before assigning a license (cloud property)' }
                @{ Name = 'userType';       Label = 'User Type';              Input = 'Choice';   Writable = $true; Required = $false; DefaultShow = $false; Authority = 'Cloud'; Choices = @('Member', 'Guest') }
            )
        }
        @{
            Name = 'Job & Organization'
            Attributes = @(
                @{ Name = 'jobTitle';         Label = 'Job Title';        Input = 'Text';   Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $true }
                @{ Name = 'department';       Label = 'Department';       Input = 'Text';   Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $true }
                @{ Name = 'manager';          Label = 'Manager';          Input = 'Person'; Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $true;  Multi = $false; TargetType = 'User' }
                @{ Name = 'companyName';      Label = 'Company Name';     Input = 'Text';   Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'employeeId';       Label = 'Employee ID';      Input = 'Text';   Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'employeeType';     Label = 'Employee Type';    Input = 'Text';   Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'employeeHireDate'; Label = 'Hire Date';        Input = 'Date';   Writable = $true; Required = $false; DefaultShow = $false; Authority = 'Cloud'; Help = 'cloud/HR attribute; not synced from AD by default' }
                @{ Name = 'officeLocation';   Label = 'Office Location';  Input = 'Text';   Writable = $true; Required = $false; DefaultShow = $false }
            )
        }
        @{
            Name = 'Contact'
            Attributes = @(
                @{ Name = 'mobilePhone';    Label = 'Mobile Phone';    Input = 'Text';  Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'businessPhones'; Label = 'Business Phones'; Input = 'Multi'; Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'otherMails';     Label = 'Other Emails';    Input = 'Multi'; Writable = $true; Required = $false; DefaultShow = $false }
            )
        }
        @{
            Name = 'Address'
            Attributes = @(
                @{ Name = 'streetAddress';     Label = 'Street Address';     Input = 'Text'; Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'city';              Label = 'City';               Input = 'Text'; Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'state';             Label = 'State / Province';   Input = 'Text'; Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'postalCode';        Label = 'Postal Code';        Input = 'Text'; Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'country';           Label = 'Country';            Input = 'Text'; Writable = $true; Required = $false; DefaultShow = $false }
                @{ Name = 'preferredLanguage'; Label = 'Preferred Language'; Input = 'Text'; Writable = $true; Required = $false; DefaultShow = $false; Help = 'e.g. en-US' }
            )
        }
        @{
            Name = 'Licensing'
            Attributes = @(
                @{ Name = 'assignedLicenses'; Label = 'Licenses'; Input = 'License'; Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $false; Authority = 'Cloud'; Help = 'usage location must be set first. License assignment is always a cloud operation, even for synced users' }
            )
        }
        @{
            Name = 'Directory Sync (read-only)'
            Attributes = @(
                @{ Name = 'onPremisesSyncEnabled';       Label = 'Directory Synced';       Input = 'ReadOnly'; Writable = $false; Required = $false; DefaultShow = $true }
                @{ Name = 'onPremisesSamAccountName';    Label = 'On-prem SamAccountName'; Input = 'ReadOnly'; Writable = $false; Required = $false; DefaultShow = $false }
                @{ Name = 'onPremisesUserPrincipalName'; Label = 'On-prem UPN';            Input = 'ReadOnly'; Writable = $false; Required = $false; DefaultShow = $false }
            )
        }
        @{
            Name = 'Exchange Extension Attributes'
            Attributes = @(
                @{ Name = 'extensionAttribute1';  Label = 'Extension Attribute 1';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute2';  Label = 'Extension Attribute 2';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute3';  Label = 'Extension Attribute 3';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute4';  Label = 'Extension Attribute 4';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute5';  Label = 'Extension Attribute 5';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute6';  Label = 'Extension Attribute 6';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute7';  Label = 'Extension Attribute 7';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute8';  Label = 'Extension Attribute 8';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute9';  Label = 'Extension Attribute 9';  Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute10'; Label = 'Extension Attribute 10'; Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute11'; Label = 'Extension Attribute 11'; Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute12'; Label = 'Extension Attribute 12'; Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute13'; Label = 'Extension Attribute 13'; Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute14'; Label = 'Extension Attribute 14'; Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
                @{ Name = 'extensionAttribute15'; Label = 'Extension Attribute 15'; Input = 'ExtAttr'; Writable = $true; Required = $false; DefaultShow = $false; MaxLength = 1024 }
            )
        }
    )

    Group = @(
        @{
            Name = 'Identity'
            Attributes = @(
                @{ Name = '__groupType';  Label = 'Group Type';      Input = 'GroupType'; Writable = $true;  Required = $true;  DefaultShow = $true;  Authority = 'Cloud'; Help = 'Security or Microsoft 365; create-time only (the tool only creates cloud groups); cannot be changed after creation' }
                @{ Name = 'displayName';  Label = 'Display Name';    Input = 'Text';      Writable = $true;  Required = $true;  DefaultShow = $true;  MaxLength = 256 }
                @{ Name = 'mailNickname'; Label = 'Mail Nickname';   Input = 'Text';      Writable = $true;  Required = $true;  DefaultShow = $true;  MaxLength = 64; Help = 'no spaces; ASCII only' }
                @{ Name = 'description';  Label = 'Description';     Input = 'Multi';     Writable = $true;  Required = $false; ShowOnNew = $true; DefaultShow = $true }
                @{ Name = 'visibility';   Label = 'Visibility';      Input = 'Choice';    Writable = $true;  Required = $false; ShowOnNew = $true; DefaultShow = $false; Authority = 'Cloud'; Choices = @('Public', 'Private'); Help = 'Microsoft 365 groups only (cloud concept; has no on-prem AD equivalent)' }
                @{ Name = 'id';           Label = 'Object ID';       Input = 'ReadOnly';  Writable = $false; Required = $false; DefaultShow = $false }
                @{ Name = 'mail';         Label = 'Email';           Input = 'ReadOnly';  Writable = $false; Required = $false; DefaultShow = $true }
                @{ Name = 'groupTypes';   Label = 'Group Types';     Input = 'ReadOnly';  Writable = $false; Required = $false; DefaultShow = $false }
            )
        }
        @{
            Name = 'Membership'
            Attributes = @(
                @{ Name = 'members'; Label = 'Members'; Input = 'Person'; Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $true; Multi = $true; TargetType = 'Any' }
                @{ Name = 'owners';  Label = 'Owners';  Input = 'Person'; Writable = $true; Required = $false; ShowOnNew = $true; DefaultShow = $true; Multi = $true; TargetType = 'User' }
            )
        }
    )

    # =====================================================================================
    #  Exchange tab  --  recipients that ONLY Exchange Online PowerShell can manage.
    #  Each object Type maps to a backend; each attribute lists the Types it applies to, so the
    #  form swaps fields when the selected object type changes. Person fields use PickerSource
    #  'Exchange' so the picker searches Exchange recipients (works without a Graph connection).
    # =====================================================================================
    Exchange = @{
        Types = @(
            @{ Key = 'Distribution'; Label = 'Distribution list';           Backend = 'DistributionGroup'; DlType = 'Distribution' }
            @{ Key = 'MailSecurity'; Label = 'Mail-enabled security group'; Backend = 'DistributionGroup'; DlType = 'Security' }
            @{ Key = 'Shared';       Label = 'Shared mailbox';              Backend = 'Mailbox';           MailboxSwitch = 'Shared' }
            @{ Key = 'Room';         Label = 'Room mailbox';                Backend = 'Mailbox';           MailboxSwitch = 'Room' }
            @{ Key = 'Equipment';    Label = 'Equipment mailbox';           Backend = 'Mailbox';           MailboxSwitch = 'Equipment' }
        )
        Groups = @(
            @{
                Name = 'Identity'
                Attributes = @(
                    @{ Name = 'displayName';        Label = 'Display Name';  Input = 'Text';     Writable = $true;  Required = $true;  DefaultShow = $true;  MaxLength = 256; Types = @('Distribution', 'MailSecurity', 'Shared', 'Room', 'Equipment') }
                    @{ Name = 'alias';              Label = 'Alias';         Input = 'Text';     Writable = $true;  Required = $true;  DefaultShow = $true;  MaxLength = 64; Help = 'mail nickname; no spaces'; Types = @('Distribution', 'MailSecurity', 'Shared', 'Room', 'Equipment') }
                    @{ Name = 'primarySmtpAddress'; Label = 'Primary Email'; Input = 'Text';     Writable = $true;  Required = $false; DefaultShow = $true;  Help = 'optional; e.g. team@contoso.com (defaults from alias)'; Types = @('Distribution', 'MailSecurity', 'Shared', 'Room', 'Equipment') }
                    @{ Name = 'name';               Label = 'Name';          Input = 'ReadOnly'; Writable = $false; Required = $false; DefaultShow = $false; Types = @('Distribution', 'MailSecurity', 'Shared', 'Room', 'Equipment') }
                )
            }
            @{
                Name = 'Options'
                Attributes = @(
                    @{ Name = 'requireSenderAuthenticationEnabled'; Label = 'Require authenticated senders'; Input = 'Bool'; Writable = $true; Required = $false; DefaultShow = $true;  Help = 'uncheck to allow external / unauthenticated senders'; Types = @('Distribution', 'MailSecurity') }
                    @{ Name = 'hiddenFromAddressListsEnabled';      Label = 'Hidden from address lists';     Input = 'Bool'; Writable = $true; Required = $false; DefaultShow = $false; Types = @('Distribution', 'MailSecurity', 'Shared', 'Room', 'Equipment') }
                )
            }
            @{
                Name = 'Membership'
                Attributes = @(
                    @{ Name = 'members';   Label = 'Members'; Input = 'Person'; Writable = $true; Required = $false; DefaultShow = $true; Multi = $true; TargetType = 'Any';  PickerSource = 'Exchange'; Types = @('Distribution', 'MailSecurity') }
                    @{ Name = 'managedBy'; Label = 'Owners';  Input = 'Person'; Writable = $true; Required = $true;  DefaultShow = $true; Multi = $true; TargetType = 'User'; PickerSource = 'Exchange'; Help = 'at least one owner is required'; Types = @('Distribution', 'MailSecurity') }
                )
            }
            @{
                Name = 'Delegation'
                Attributes = @(
                    @{ Name = 'fullAccess';   Label = 'Full Access';    Input = 'Person'; Writable = $true; Required = $false; DefaultShow = $true;  Multi = $true; TargetType = 'Any'; PickerSource = 'Exchange'; Help = 'can open the mailbox';   Types = @('Shared', 'Room', 'Equipment') }
                    @{ Name = 'sendAs';       Label = 'Send As';        Input = 'Person'; Writable = $true; Required = $false; DefaultShow = $true;  Multi = $true; TargetType = 'Any'; PickerSource = 'Exchange'; Help = 'can send as the mailbox'; Types = @('Shared', 'Room', 'Equipment') }
                    @{ Name = 'sendOnBehalf'; Label = 'Send on Behalf'; Input = 'Person'; Writable = $true; Required = $false; DefaultShow = $false; Multi = $true; TargetType = 'Any'; PickerSource = 'Exchange'; Types = @('Shared', 'Room', 'Equipment') }
                )
            }
        )
    }
}
