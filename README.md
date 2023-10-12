### qubes-yubioath

----

*qubes-yubioath* is a [rofi](https://github.com/davatorium/rofi) based frontend for some of the OTP related functionality
of [yubikey-manager](https://github.com/Yubico/yubikey-manager). It can be used to obtain OTP secrets from your *YubiKey*
and integrates nicely with the isolation and security features of [Qubes OS](https://www.qubes-os.org/).

<div align="center">
  <img src="https://github.com/codewhitesec/qubes-yubioath/assets/49147108/6dbf4bf2-2fc3-4439-90aa-b1aecce006ea"/>
</div>
<br/>

*qubes-yubioath* is inspired by [qubes-keepass](https://github.com/codewhitesec/qubes-keepass) which provides a *rofi* based
frontend for the password manager [KeePassXC](https://keepassxc.org/).


### Installation

----

*qubes-yubioath* relies on *Qubes qrexec* mechanism and requires multiple installation steps in different Qubes. In the
following, it is assumed that your *YubiKey* is attached to a qube named `vault`, that your window manager
is [i3](https://www.qubes-os.org/doc/i3/) and that you have an *AppVM Qube* called `app-vm`. In addition, make sure that
*rofi* and *yubikey-manager* are installed in the `vault` qube and *xclip* is installed in the `app-vm` qube.

If you already installed [qubes-keepass](https://github.com/codewhitesec/qubes-keepass), some installation steps can
be skipped.

#### dom0

In `dom0` create a policy file for the `custom.QubesKeepass` *qrexec* service (yes, we use the same service as
[qubes-keepass](https://github.com/codewhitesec/qubes-keepass) here, as both services have identical functionality).
This service will be invoked by your `vault` qube to copy OTP codes to other *AppVMs*:

```console
[user@dom0 ~]$ cat /etc/qubes-rpc/policy/custom.QubesKeepass
vault $anyvm allow notify=true
```

According to your preferences, you could also choose `ask` instead of the `allow` action or remove the `notify=true` option,
if you do not want to be notified when something gets copied via *qubes-yubioath*.

If you're using Qubes 4.1 and want to follow the new *qrexec* policy system:

```console
[user@dom0 ~]$ cat /etc/qubes/policy.d/30-user.policy
...
custom.QubesKeepass * vault @anyvm allow notify=yes
```

Now copy the [qubes-yubioath-dom0.sh](./qubes-yubioath-dom0.sh) script to a location within your `$PATH` environment variable
and make sure that it is executable.

Finally, set up a shortcut for invoking `qubes-yubioath-dom0.sh` in your *i3* configuration file and make sure that
the window class `Rofi` is configured to floating:

```console
[user@dom0 ~]$ cat /.config/i3/config
...
bindsym $mod+P exec --no-startup-id qubes-yubioath-dom0.sh
for_window [class="Rofi"] floating enable
```


#### vault

In your `vault` qube you only need to copy the [qubes-yubioath.py](./qubes-yubioath.py) script to a folder that is also contained
within your `PATH` environment variable and to make sure that the script is executable. Make sure that the location of the script
matches the location specified in [qubes-yubioath-dom0.sh](./qubes-yubioath-dom0.sh) (default is `/home/user/.local/bin/qubes-yubioath.py`).
Also the configuration file [qubes-yubioath.ini](./qubes-yubioath.ini) needs to be copied to your `vault` VM. A good location for this one
is `/home/user/.config/qubes-yubioath.ini`.


#### app-vm

For each *AppVM* that is allowed to obtain OTP secrets from *qubes-yubioath*, you need to setup an *qrexec* service. This service
is essentially just a pipe to `xclip` and looks like this:

```console
[user@app-vm ~]$ cat /etc/qubes-rpc/custom.QubesKeepass
#!/usr/bin/sh

xclip -selection clipboard
```

Make sure that it is executable and that such a file exists on each *AppVM* you want to use *qubes-yubioath* with. As the *qrexec*
service is defined outside the persistent portions of an *AppVM*, you probably want to set it up within the *AppVMs* template.


### Usage

----

After pressing the configured shortcut for `qubes-yubioath-dom0.sh`, *qubes-yubioath* determines your currently focused qube
and displays available OTP secrets in *rofi*. After you selected an OTP secret, an OTP code is calculated and copied to
the previously determined qube using the `custom.QubesKeepass` *qrexec* service.


### Configuration

----

*qubes-yubioath* supports some custom configuration options, like the parameters that are used when executing *rofi* or the
icons that are displayed for each OTP issuer. Configuration takes place in an `.ini` file that is searched within the following
locations:

* ~/.config/qubes-keepass.ini
* ~/.config/qubes-keepass/config.ini
* ~/.config/qubes-keepass/qubes-keepass.ini
* /etc/qubes-keepass.ini
* /etc/qubes-keepass/config.ini
* /etc/qubes-keepass/qubes-keepass.ini

#### Global Options

* `smart_sort` - sort OTP secrets by their usage count. An OTP secret accessed within the last 30 seconds is always displayed first

#### Provider Options

*qubes-yubioath* allows to specify a custom icon for each OTP issuer. The following listing shows an example, where icons for
two issuers were configured:

```ini
[qubes.yubioath.providers]
Outlook = /path/to/outlook/icon.png
Office365 = /path/to/office365/icon.png
```

#### Rofi Options

Within the section `rofi.options` you can specify arbitrary options that are passed to `rofi` when executing it. 
