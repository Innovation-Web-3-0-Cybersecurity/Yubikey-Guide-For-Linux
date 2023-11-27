# Yubikey-Guide-For-Linux 

Welcome to the `Yubikey-Guide-For-Linux`. This guide illustrates the usage of the [YubiKey](https://www.yubico.com/products/yubikey-hardware/) as a smartCard for storing GPG encryption, signing, and authentication keys, which can also be used for SSH. Many of the principles in this document are applicable to other smart card devices.

## Table of Contents

- [Special Note](#special-note)
- [Purchase](#purchase)
- [Security Note](#security-note)
- [Securing Your Environment](#securing-your-environment)
- [Getting Started](#getting-started)
- [Required Software](#required-software)
  - [Debian and Ubuntu](#debian-and-ubuntu)
  - [Fedora](#fedora)
  - [Arch](#arch)
  - [RHEL7](#rhel7)
  - [NixOs ](#nixos)
- [Entropy](#entropy)
  - [Yubikey](#yubikey)
  - [OneRNG](#onerng)
- [Creating Keys](#creating-keys)
  - [Temporary Working Directory](#temporary-working-directory)
  - [Harden Configuration](#harden-configuration)
  - [Preserving Working Directory](#preserving-working-directory)
- [Master Key](#master-key)
- [Sign With Existing Key](#sign-with-existing-key)
- [Sub-Keys](#subs-keys)
  - [Signing](#signing)
  - [Encryption](#encryption)
  - [Authentication](#authentication)
  - [Add Extra Identities](#add-extra-identities)
- [Verify GPG Keys](#verify-gpg-keys)
- [Export Secret Keys](#export-secret-keys)
- [Revocation Certificate](#revocation-certificate)
- [Backup](#backup)
- [Export Public Keys](#export-public-keys)
- [Keyserver](#keyserver)
- [Configure Smartcard](#configure-smartcard)


## Special Note 

We are not affiliated with Yubico, and this guide is not an original creation. Instead, we've replicated it from the [drhub YubiKey-Guide repository](https://github.com/drduh/YubiKey-Guide). Our intention is to tailor the content specifically for Linux users, simplifying the guide to enhance its accessibility for beginners.

## Purchase

All YubiKeys except the blue "security key" model and the "Bio Series - FIDO Edition" are compatible with this guide. NEO models are limited to 2048-bit RSA keys. Compare YubiKeys [here](https://www.yubico.com/products/yubikey-hardware/compare-products-series/). A list of the YubiKeys compatible with OpenPGP is available [here](https://support.yubico.com/hc/en-us/articles/360013790259-Using-Your-YubiKey-with-OpenPGP). In May 2021, Yubico also released a press release and blog post about supporting resident ssh keys on their Yubikeys, including blue "security key 5 NFC" with OpenSSH 8.2 or later, see [here](https://www.yubico.com/blog/github-now-supports-ssh-security-keys/) for details.

## Security Note 

**NEVER TRUST, ALWAYS VERIFY**

To verify a YubiKey is genuine, open a [browser with U2F support](https://support.yubico.com/support/solutions/articles/15000009591-how-to-confirm-your-yubico-device-is-genuine-with-u2f) to [https://www.yubico.com/genuine/](https://www.yubico.com/genuine/). Insert a Yubico device, and select *Verify Device* to begin the process. Touch the YubiKey when prompted, and if asked, allow it to see the make and model of the device. If you see *Verification complete*, the device is authentic.

This website verifies YubiKey device attestation certificates signed by a set of Yubico certificate authorities and helps mitigate [supply chain attacks](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20r00killah-and-securelyfitz-Secure-Tokin-and-Doobiekeys.pdf).

## Securing Your Environment

To create cryptographic keys, a secure environment that can be reasonably assured to be free of adversarial control is recommended. Here is a general ranking of environments most to least likely to be compromised:

1. Daily-use operating system
2. Virtual machine on a daily-use host OS (using [virt-manager](https://virt-manager.org/), VirtualBox, or VMware)
3. Separate hardened [Debian](https://www.debian.org/) or [OpenBSD](https://www.openbsd.org/) installation that can be dual-booted
4. Live image, such as [Debian Live](https://www.debian.org/CD/live/) or [Tails](https://tails.boum.org/index.en.html)
5. Secure hardware/firmware ([Coreboot](https://www.coreboot.org/), [Intel ME removed](https://github.com/corna/me_cleaner))
6. Dedicated air-gapped system with no networking capabilities

# Getting Started

This guide recommends using a bootable "live" Debian Linux image to provide such an environment, however, depending on your threat model, you may want to take fewer or more steps to secure it.

To use Debian Live, download the latest image:

```console
$ curl -LfO https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/SHA512SUMS

$ curl -LfO https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/SHA512SUMS.sign

$ curl -LfO https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/$(awk '/xfce.iso/ {print $2}' SHA512SUMS)
```

1. Verify the signature of the hashes file with GPG:

```console
$ gpg --verify SHA512SUMS.sign SHA512SUMS
gpg: Signature made Sat 07 Oct 2023 01:24:57 PM PDT
gpg:                using RSA key DF9B9C49EAA9298432589D76DA87E80D6294BE9B
gpg: Can't check signature: No public key

$ gpg --keyserver hkps://keyring.debian.org --recv DF9B9C49EAA9298432589D76DA87E80D6294BE9B
gpg: key 0xDA87E80D6294BE9B: public key "Debian CD signing key <debian-cd@lists.debian.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1

$ gpg --verify SHA512SUMS.sign SHA512SUMS
gpg: Signature made Sat 07 Oct 2023 01:24:57 PM PDT
gpg:                using RSA key DF9B9C49EAA9298432589D76DA87E80D6294BE9B
gpg: Good signature from "Debian CD signing key <debian-cd@lists.debian.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: DF9B 9C49 EAA9 2984 3258  9D76 DA87 E80D 6294 BE9B
```

If the public key cannot be received, try changing the DNS resolver and/or use a different keyserver:

```console
$ gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv DF9B9C49EAA9298432589D76DA87E80D6294BE9B
```

2. Ensure the SHA512 hash of the live image matches the one in the signed file - if there following command produces output, it is correct:

```console
$ grep $(sha512sum debian-live-*-amd64-xfce.iso) SHA512SUMS
SHA512SUMS:3c74715380c804798d892f55ebe4d2f79ae266be93df2468a066c192cfe1af6ddae3139e1937d5cbfa2fccb6fe291920148401de30f504c0876be2f141811ff1  debian-live-12.2.0-amd64-xfce.iso
```

See [Verifying authenticity of Debian CDs](https://www.debian.org/CD/verify) for more information.

3. Mount a storage device and copy the image to it:

```console
$ sudo dmesg | tail
usb-storage 3-2:1.0: USB Mass Storage device detected
scsi host2: usb-storage 3-2:1.0
scsi 2:0:0:0: Direct-Access     TS-RDF5  SD  Transcend    TS3A PQ: 0 ANSI: 6
sd 2:0:0:0: Attached scsi generic sg1 type 0
sd 2:0:0:0: [sdb] 31116288 512-byte logical blocks: (15.9 GB/14.8 GiB)
sd 2:0:0:0: [sdb] Write Protect is off
sd 2:0:0:0: [sdb] Mode Sense: 23 00 00 00
sd 2:0:0:0: [sdb] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
sdb: sdb1 sdb2
sd 2:0:0:0: [sdb] Attached SCSI removable disk

$ sudo dd if=debian-live-*-amd64-xfce.iso of=/dev/sdb bs=4M status=progress ; sync
465+1 records in
465+1 records out
1951432704 bytes (2.0 GB, 1.8 GiB) copied, 42.8543 s, 45.5 MB/s
```

# Required Software

Boot the live image and configure networking.

**Note** If the screen locks, unlock with `user`/`live`.

Open the terminal and install required software packages.

## Debian and Ubuntu

```console
$ sudo apt update

$ sudo apt -y upgrade

$ sudo apt -y install wget gnupg2 gnupg-agent dirmngr cryptsetup scdaemon pcscd secure-delete hopenpgp-tools yubikey-personalization
```

**Note**
As of 2023 June, the `hopenpgp-tools` is not part of the latest Debian 12 stable package repositories.

To install it, go to [https://packages.debian.org/sid/hopenpgp-tools](https://packages.debian.org/sid/hopenpgp-tools) to select your architecture and then an ftp server.

Edit `/etc/apt/sources.list` and add the ftp server:
```
deb http://ftp.debian.org/debian sid main
```

and then add this to `/etc/apt/preferences` (or a fragment, e.g. `/etc/apt/preferences.d/00-sid`) so that APT still prioritizes packages from the stable repository over sid.

```
Package: *
Pin: release n=sid
Pin-Priority: 10
```

**Note** Live Ubuntu images [may require modification](https://github.com/drduh/YubiKey-Guide/issues/116) to `/etc/apt/sources.list` and may need additional packages:

```console
$ sudo apt -y install libssl-dev swig libpcsclite-dev
```

**Optional** Install the `ykman` utility, which will allow you to enable touch policies (requires admin PIN):

```console
$ sudo apt -y install python3-pip python3-pyscard

$ pip3 install PyOpenSSL

$ pip3 install yubikey-manager

$ sudo service pcscd start

$ ~/.local/bin/ykman openpgp info
```

**Note** Debian 12 doesn't recommend installing non-Debian packaged Python applications globally. But fortunately, it isn't even necessary as `yubikey-manager` is available in the stable main repository:
`$ sudo apt install yubikey-manager`.

## Fedora

```console
$ sudo dnf install wget

$ wget https://github.com/rpmsphere/noarch/raw/master/r/rpmsphere-release-38-1.noarch.rpm

$ sudo rpm -Uvh rpmsphere-release*rpm

$ sudo dnf install gnupg2 dirmngr cryptsetup gnupg2-smime pcsc-tools opensc pcsc-lite secure-delete pgp-tools yubikey-personalization-gui
```

## Arch

```console
$ sudo pacman -Syu gnupg pcsclite ccid hopenpgp-tools yubikey-personalization
```

## RHEL7

```console
$ sudo yum install -y gnupg2 pinentry-curses pcsc-lite pcsc-lite-libs gnupg2-smime
```

## NixOS

Generate an air-gapped NixOS LiveCD image with the given config:

```nix
# yubikey-installer.nix
let
  configuration = { config, lib, pkgs, ... }:
    with pkgs;
    let
      src = fetchGit "https://github.com/drduh/YubiKey-Guide";

      guide = "${src}/README.md";

      contrib = "${src}/contrib";

      drduhConfig = fetchGit "https://github.com/drduh/config";

      gpg-conf = "${drduhConfig}/gpg.conf";

      xserverCfg = config.services.xserver;

      pinentryFlavour = if xserverCfg.desktopManager.lxqt.enable || xserverCfg.desktopManager.plasma5.enable then
        "qt"
      else if xserverCfg.desktopManager.xfce.enable then
        "gtk2"
      else if xserverCfg.enable || config.programs.sway.enable then
        "gnome3"
      else
        "curses";

      # Instead of hard-coding the pinentry program, chose the appropriate one
      # based on the environment of the image the user has chosen to build.
      gpg-agent-conf = runCommand "gpg-agent.conf" {} ''
        sed '/pinentry-program/d' ${drduhConfig}/gpg-agent.conf > $out
        echo "pinentry-program ${pinentry.${pinentryFlavour}}/bin/pinentry" >> $out
      '';

      view-yubikey-guide = writeShellScriptBin "view-yubikey-guide" ''
        viewer="$(type -P xdg-open || true)"
        if [ -z "$viewer" ]; then
          viewer="${glow}/bin/glow -p"
        fi
        exec $viewer "${guide}"
      '';

      shortcut = makeDesktopItem {
        name = "yubikey-guide";
        icon = "${yubikey-manager-qt}/share/ykman-gui/icons/ykman.png";
        desktopName = "drduh's YubiKey Guide";
        genericName = "Guide to using YubiKey for GPG and SSH";
        comment = "Open the guide in a reader program";
        categories = [ "Documentation" ];
        exec = "${view-yubikey-guide}/bin/view-yubikey-guide";
      };

      yubikey-guide = symlinkJoin {
        name = "yubikey-guide";
        paths = [ view-yubikey-guide shortcut ];
      };

    in {
      nixpkgs.overlays = [
        # hopenpgp-tools in nixpkgs 23.05 is out-of-date and has a broken build
        (final: prev: {
          haskellPackages = prev.haskellPackages.override {
            overrides = hsFinal: hsPrev:
              let
                optparse-applicative =
                  final.haskell.lib.overrideCabal hsPrev.optparse-applicative
                  (oldAttrs: {
                    version = "0.18.1.0";
                    sha256 =
                      "sha256-Y4EatP0m6Cm4hoNkMlqIvjrMeYGfW7UAWy3TuWHsxJE=";
                    libraryHaskellDepends =
                      (oldAttrs.libraryHaskellDepends or [ ])
                      ++ (with hsFinal; [
                        text
                        prettyprinter
                        prettyprinter-ansi-terminal
                      ]);
                  });
                hopenpgp-tools =
                  (final.haskell.lib.overrideCabal hsPrev.hopenpgp-tools
                    (oldAttrs: {
                      version = "0.23.8";
                      sha256 =
                        "sha256-FYvlVE0o/LOYk3a2rucAqm7tg5D/uNQRRrCu/wlDNAE=";
                      broken = false;
                    })).override { inherit optparse-applicative; };
              in { inherit hopenpgp-tools; };
          };
        })
      ];

      isoImage.isoBaseName = lib.mkForce "nixos-yubikey";
      # Uncomment this to disable compression and speed up image creation time
      #isoImage.squashfsCompression = "gzip -Xcompression-level 1";

      # Always copytoram so that, if the image is booted from, e.g., a
      # USB stick, nothing is mistakenly written to persistent storage.
      boot.kernelParams = [ "copytoram" ];
      # Secure defaults
      boot.cleanTmpDir = true;
      boot.kernel.sysctl = { "kernel.unprivileged_bpf_disabled" = 1; };

      services.pcscd.enable = true;
      services.udev.packages = [ yubikey-personalization ];

      programs = {
        ssh.startAgent = false;
        gnupg.agent = {
          enable = true;
          enableSSHSupport = true;
        };
      };

      environment.systemPackages = [
        # Tools for backing up keys
        paperkey
        pgpdump
        parted
        cryptsetup

        # Yubico's official tools
        yubikey-manager
        yubikey-manager-qt
        yubikey-personalization
        yubikey-personalization-gui
        yubico-piv-tool
        yubioath-flutter

        # Testing
        ent
        (haskell.lib.justStaticExecutables haskellPackages.hopenpgp-tools)

        # Password generation tools
        diceware
        pwgen

        # Miscellaneous tools that might be useful beyond the scope of the guide
        cfssl
        pcsctools

        # This guide itself (run `view-yubikey-guide` on the terminal to open it
        # in a non-graphical environment).
        yubikey-guide
      ];

      # Disable networking so the system is air-gapped
      # Comment all of these lines out if you'll need internet access
      boot.initrd.network.enable = false;
      networking.dhcpcd.enable = false;
      networking.dhcpcd.allowInterfaces = [];
      networking.interfaces = {};
      networking.firewall.enable = true;
      networking.useDHCP = false;
      networking.useNetworkd = false;
      networking.wireless.enable = false;
      networking.networkmanager.enable = lib.mkForce false;

      # Unset history so it's never stored
      # Set GNUPGHOME to an ephemeral location and configure GPG with the
      # guide's recommended settings.
      environment.interactiveShellInit = ''
        unset HISTFILE
        export GNUPGHOME="/run/user/$(id -u)/gnupg"
        if [ ! -d "$GNUPGHOME" ]; then
          echo "Creating \$GNUPGHOME…"
          install --verbose -m=0700 --directory="$GNUPGHOME"
        fi
        [ ! -f "$GNUPGHOME/gpg.conf" ] && cp --verbose ${gpg-conf} "$GNUPGHOME/gpg.conf"
        [ ! -f "$GNUPGHOME/gpg-agent.conf" ] && cp --verbose ${gpg-agent-conf} "$GNUPGHOME/gpg-agent.conf"
        echo "\$GNUPGHOME is \"$GNUPGHOME\""
      '';

      # Copy the contents of contrib to the home directory, add a shortcut to
      # the guide on the desktop, and link to the whole repo in the documents
      # folder.
      system.activationScripts.yubikeyGuide = let
        homeDir = "/home/nixos/";
        desktopDir = homeDir + "Desktop/";
        documentsDir = homeDir + "Documents/";
      in ''
        mkdir -p ${desktopDir} ${documentsDir}
        chown nixos ${homeDir} ${desktopDir} ${documentsDir}

        cp -R ${contrib}/* ${homeDir}
        ln -sf ${yubikey-guide}/share/applications/yubikey-guide.desktop ${desktopDir}
        ln -sfT ${src} ${documentsDir}/YubiKey-Guide
      '';
    };

  nixos = import <nixpkgs/nixos/release.nix> {
    inherit configuration;
    supportedSystems = [ "x86_64-linux" ];
  };

  # Choose the one you like:
  #nixos-yubikey = nixos.iso_minimal; # No graphical environment
  #nixos-yubikey = nixos.iso_gnome;
  nixos-yubikey = nixos.iso_plasma5;

in {
  inherit nixos-yubikey;
}
```

Build the installer and copy it to a USB drive.

```console
$ nix-build yubikey-installer.nix --out-link installer --attr nixos-yubikey

$ sudo cp -v installer/iso/*.iso /dev/sdb; sync
'installer/iso/nixos-yubikey-22.05beta-248980.gfedcba-x86_64-linux.iso' -> '/dev/sdb'
```

With this image, you won't need to manually create a [temporary working directory](#temporary-working-directory) or [harden the configuration](#harden-configuration), as it was done when creating the image.


# Entropy

Generating cryptographic keys requires high-quality [randomness](https://www.random.org/randomness/), measured as entropy.

Most operating systems use software-based pseudorandom number generators or CPU-based hardware random number generators (HRNG).

Optionally, you can use a separate hardware device like [OneRNG](https://onerng.info/onerng/) to [increase the speed](https://lwn.net/Articles/648550/) of entropy generation and possibly also the quality.

## YubiKey

YubiKey firmware version 5.2.3 introduced "Enhancements to OpenPGP 3.4 Support" - which can optionally gather additional entropy from YubiKey via the SmartCard interface.

To seed the kernel's PRNG with additional 512 bytes retrieved from the YubiKey:

```console
$ echo "SCD RANDOM 512" | gpg-connect-agent | sudo tee /dev/random | hexdump -C
```

## OneRNG

Install [rng-tools](https://wiki.archlinux.org/index.php/Rng-tools) software:

```console
$ sudo apt -y install at rng-tools python3-gnupg openssl

$ wget https://github.com/OneRNG/onerng.github.io/raw/master/sw/onerng_3.7-1_all.deb

$ sha256sum onerng_3.7-1_all.deb
b7cda2fe07dce219a95dfeabeb5ee0f662f64ba1474f6b9dddacc3e8734d8f57  onerng_3.7-1_all.deb

$ sudo dpkg -i onerng_3.7-1_all.deb

$ echo "HRNGDEVICE=/dev/ttyACM0" | sudo tee /etc/default/rng-tools
```

Plug in the device and restart rng-tools:

```console
$ sudo atd

$ sudo service rng-tools restart
```

# Creating Keys

## Temporary Working Directory

Create a temporary directory that will be cleared on [reboot](https://en.wikipedia.org/wiki/Tmpfs) and set it as the GnuPG directory:

```console
$ export GNUPGHOME=$(mktemp -d -t gnupg_$(date +%Y%m%d%H%M)_XXX)
```

## Harden Configuration

Create a hardened configuration in the temporary working directory with the following options:

```console
$ wget -O $GNUPGHOME/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf

$ grep -ve "^#" $GNUPGHOME/gpg.conf
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
no-greeting
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
no-symkey-cache
use-agent
throw-keyids
```

**Tip:** Networking can be disabled for the remainder of the setup.

## Preserving Working Directory 

(Optional) To preserve the working environment, set the GnuPG directory to your home folder:

```console
$ export GNUPGHOME=~/gnupg-workspace
```

**Tip:** If you decide to preserve the working environment instead of a temporary one, make sure to disable the network for the remainder of the setup and to delete your footprint afterwards.

# Master Key

The first key to generate is the master key. It will be used for certification only: to issue sub-keys that are used for encryption, signing, and authentication.

**Important:** The master key should be kept offline at all times and only accessed to revoke or issue new sub-keys. Keys can also be generated on the YubiKey itself to ensure no other copies exist.

You'll be prompted to enter and verify a passphrase—keep it handy as you'll need it multiple times later.

1. Generate a strong passphrase which could be written down in a secure place or memorized:

```console
$ gpg --gen-random --armor 0 24
ydOmByxmDe63u7gqx2XI9eDgpvJwibNH
```

Use upper case letters for improved readability if passwords are written down by hand:

```console
$ LC_ALL=C tr -dc '[:upper:]' < /dev/urandom | fold -w 20 | head -n1
BSSYMUGGTJQVWZZWOPJG
```

**Important:** Save this credential in a permanent, secure place as it will be needed to issue new sub-keys after expiration, and to provision additional YubiKeys, as well as to your Debian Live environment clipboard, as you'll need it several times throughout to generate keys.

**Tip:** Select the password using the mouse or by double-clicking on it to copy to clipboard. Paste using the middle mouse button or `Shift`-`Insert`.

**Do not** set the master (certify) key to expire—see [Note #3](#notes).

2. Generate a new key with GPG, selecting `(8) RSA (set your own capabilities)`, `Certify` capability only, and `4096` bit key size.

```console
$ gpg --expert --full-generate-key
Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
   (9) ECC and ECC
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (13) Existing key
  (14) Existing key from card
Your selection? 8

Possible actions for an RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? E

Possible actions for an RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? S

Possible actions for an RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? Q
RSA keys may be between 1024 and 4096 bits long.
What key size do you want? (2048) 4096
Requested key size is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 0
Key does not expire at all
Is this correct? (y/N) y
```

3. Input any name and email address (it doesn't have to be valid):

```console
GnuPG needs to construct a user ID to identify your key.

Real name: Dr Duh
Email address: doc@duh.to
Comment: [Optional - leave blank]
You selected this USER-ID:
    "Dr Duh <doc@duh.to>"

Change (N)ame, (C)omment, (E)mail, or (O)kay/(Q)uit? o

We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

gpg: /tmp.FLZC0xcM/trustdb.gpg: trustdb created
gpg: key 0xFF3E7D88647EBCDB marked as ultimately trusted
gpg: directory '/tmp.FLZC0xcM/openpgp-revocs.d' created
gpg: revocation certificate stored as '/tmp.FLZC0xcM/openpgp-revocs.d/011CE16BD45B27A55BA8776DFF3E7D88647EBCDB.rev'
public and secret key created and signed.

pub   rsa4096

/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                              Dr Duh <doc@duh.to>
```

Export the key ID in gpg: key `0xFF3E7D88647EBCDB` **yours will be different** as a [variable](https://stackoverflow.com/questions/1158091/defining-a-variable-with-or-without-export/1158231#1158231) (`KEYID`) for use later:

```console
$ export KEYID=0xFF3E7D88647EBCDB
```

# Sign With Existing Key

(Optional) If you already have a PGP key, you may want to sign the new key with the old one to prove that the new key is controlled by you.

1. Export your existing key to move it to the working keyring:

```console
$ gpg --export-secret-keys --armor --output /tmp/new.sec
```

2. Export the old key ID as a variable

```console
$ export OLDKEY=0x1234567887654321
```

3. Then sign the new key: 

```console
$ gpg --default-key $OLDKEY --sign-key $KEYID
```

# Sub-Keys

Edit the master key to add sub-keys:

```console
$ gpg --expert --edit-key $KEYID

Secret key is available.

sec  rsa4096/0xEA5DE91459B80592
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
[ultimate] (1). Dr Duh <doc@duh.to>
```

Use 4096-bit RSA keys.

Use a 1-year expiration for sub-keys—they can be renewed using the offline master key. See [rotating keys](#rotating-keys).

## Signing

Create a [signing key](https://stackoverflow.com/questions/5421107/can-rsa-be-both-used-as-encryption-and-signature/5432623#5432623) by selecting `addkey` then `(4) RSA (sign only)`:

```console
gpg> addkey
Key is protected.

You need a passphrase to unlock the secret key for
user: "Dr Duh <doc@duh.to>"
4096-bit RSA key, ID 0xFF3E7D88647EBCDB, created 2016-05-24

Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
Your selection? 4
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Encryption

Next, create an [encryption key](https://www.cs.cornell.edu/courses/cs5430/2015sp/notes/rsa_sign_vs_dec.php) by selecting `(6) RSA (encrypt only)`:

```console
gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
Your selection? 6
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2019 00:00:00 UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2019-10-09       usage: E
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Authentication

Finally, create an [authentication key](https://superuser.com/questions/390265/what-is-a-gpg-with-authenticate-capability-used-for).

GPG doesn't provide an authenticate-only key type, so select `(8) RSA (set your own capabilities)` and toggle the required capabilities until the only allowed action is `Authenticate`:

```console
gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
Your selection? 8

Possible actions for an RSA key: Sign Encrypt Authenticate
Current allowed actions: Sign Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? S

Possible actions for an RSA key: Sign Encrypt Authenticate
Current allowed actions: Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? E

Possible actions for an RSA key: Sign Encrypt Authenticate
Current allowed actions:

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? A

Possible actions for an RSA key: Sign Encrypt Authenticate
Current allowed actions: Authenticate

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? Q
RSA keys may be between 1024 and 4096 bits long.
What key size do you want? (2048) 4096
Requested key size is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
```

Finish by saving the keys.

```console
gpg> save
```

## Add Extra Identities

(Optional) To add additional email addresses or identities, use `adduid`.

First, open the keyring:

```console
$ gpg --expert --edit-key $KEYID
```

Then add the new identity:

```console
gpg> adduid
Real name: Dr Duh
Email address: DrDuh@other.org
Comment:
You selected this USER-ID:
    "Dr Duh <DrDuh@other.org>"

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

gpg> trust
sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage:

 S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

gpg> uid 1

sec  rsa4096/0xFF3E7D88647EBCDB
created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1)* Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

gpg> primary

sec  rsa4096/0xFF3E7D88647EBCDB
created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1)* Dr Duh <doc@duh.to>
[ unknown] (2)  Dr Duh <DrDuh@other.org>

gpg> save
```

By default, the last identity added will be the primary user ID - use `primary` to change that.

# Verify GPG Keys

List the generated secret keys and verify the output:

```console
$ gpg -K
/tmp.FLZC0xcM/pubring.kbx
-------------------------------------------------------------------------
sec   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                            Dr Duh <doc@duh.to>
ssb   rsa4096/0xBECFA3C1AE191D15 2017-10-09 [S] [expires: 2018-10-09]
ssb   rsa4096/0x5912A795E90DD2CF 2017-10-09 [E] [expires: 2018-10-09]
ssb   rsa4096/0x3F29127E79649A3D 2017-10-09 [A] [expires: 2018-10-09]
```

Add any additional identities or email addresses you wish to associate using the `adduid` command.

**Tip:** Verify with an OpenPGP [key best practice checker](https://riseup.net/en/security/message-security/openpgp/best-practices#openpgp-key-checks):

```console
$ gpg --export $KEYID | hokey lint
```

The output will display any problems with your key in red text. If everything is green, your key passes each of the tests. If it is red, your key has failed one of the tests.

> `hokey` may warn (orange text) about cross certification for the authentication key. GPG's [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html) documentation has more detail on cross certification, and GPG v2.2.1 notes "subkey <keyid> does not sign and so does not need to be cross-certified". `hokey` may also indicate a problem (red text) with `Key expiration times: []` on the primary key (see [Note #3](#notes) about not setting an expiry for the primary key).

# Export Secret Keys

The master key and sub-keys will be encrypted with your passphrase when exported.

Save a copy of your keys:

```console
$ gpg --armor --export-secret-keys $KEYID > $GNUPGHOME/mastersub.key

$ gpg --armor --export-secret-subkeys $KEYID > $GNUPGHOME/sub.key
```

# Revocation Certificate

Although we will backup and store the master key in a safe place, it is best practice to never rule out the possibility of losing it or having the backup fail. Without the master key, it will be impossible to renew or rotate subkeys or generate a revocation certificate, and the PGP identity will be useless.

Even worse, we cannot advertise this fact in any way to those that are using our keys. It is reasonable to assume this *will* occur at some point, and the only remaining way to deprecate orphaned keys is a revocation certificate.

To create the revocation certificate:

```console
$ gpg --output $GNUPGHOME/revoke.asc --gen-revoke $KEYID
```

The `revoke.asc` certificate file should be stored (or printed) in a (secondary) place that allows retrieval in case the main backup fails.

# Backup

Once keys are moved to YubiKey, they cannot be moved again! Create an **encrypted** backup of the keyring on removable media so you can keep it offline in a safe place.

**Tip:** The ext2 filesystem (without encryption) can be mounted on both Linux and OpenBSD.

As an additional backup measure, consider using a [paper copy](https://www.jabberwocky.com/software/paperkey/) of the keys. The [Linux Kernel Maintainer PGP Guide](https://www.kernel.org/doc/html/latest/process/maintainer-pgp-guide.html#back-up-your-master-key-for-disaster-recovery) points out that such printouts *are still password-protected*. It recommends writing the password on the paper, as it will be unlikely that you remember the original key password used when the paper backup was created. Obviously, you need a really good place to keep such a printout.

It is strongly recommended to keep even encrypted OpenPGP private key material offline to deter [key overwriting attacks](https://www.kopenpgp.com/), for example.

1. Attach another external storage device and check its label:

```console
$ sudo dmesg | tail
mmc0: new high-speed SDHC card at address a001
mmcblk0: mmc0:a001 SS16G 14.8 GiB

$ sudo fdisk -l /dev/mmcblk0
Disk /dev/mmcblk0: 14.9 GiB, 15931539456 bytes, 31116288 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

2. Write it with random data to prepare for encryption:

```console
$ sudo dd if=/dev/urandom of=/dev/mmcblk0 bs=4M status=progress
```

**Do not** remove your external drive until the data writing is done.

3. Erase and create a new partition table:

```console
$ sudo fdisk /dev/mmcblk0

Welcome to fdisk (util-linux 2.33.1).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Device does not contain a recognized partition table.
Created a new DOS disk label with disk identifier 0x3c1ad14a.

Command (m for help): g
Created a new GPT disk label (GUID: 4E7495FD-85A3-3E48-97FC-2DD8D41516C3).

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.
```

4. Create a new partition with a 25 Megabyte size:

```console
$ sudo fdisk /dev/mmcblk0

Welcome to fdisk (util-linux 2.36.1).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Command (m for help): n
Partition number (1-128, default 1):
First sector (2048-30261214, default 2048):
Last sector, +/-sectors or +/-size{K,M,G,T,P} (2048-30261214, default 30261214): +25M

Created a new partition 1 of type 'Linux filesystem' and of size 25 MiB.

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.
```

5. Use [LUKS](

https://askubuntu.com/questions/97196/how-secure-is-an-encrypted-luks-filesystem) to encrypt the new partition. Generate a different password which will be used to protect the filesystem:

```console
$ sudo cryptsetup luksFormat /dev/mmcblk0p1

WARNING!
========
This will overwrite data on /dev/mmcblk0p1 irrevocably.

Are you sure? (Type uppercase yes): YES
Enter passphrase for /dev/mmcblk0p1:
Verify passphrase:
```

6. Mount the partition:

```console
$ sudo cryptsetup luksOpen /dev/mmcblk0p1 secret
Enter passphrase for /dev/mmcblk0p1:
```

7. Create an ext2 filesystem:

```console
$ sudo mkfs.ext2 /dev/mapper/secret -L gpg-$(date +%F)
```

8. Mount the filesystem and copy the temporary GnuPG directory with the keyring:

```console
$ sudo mkdir /mnt/encrypted-storage

$ sudo mount /dev/mapper/secret /mnt/encrypted-storage

$ sudo cp -avi $GNUPGHOME /mnt/encrypted-storage/
```

9. **Optional:** Backup the OneRNG package:

```console
$ sudo cp onerng_3.7-1_all.deb /mnt/encrypted-storage/
```

**Note:** If you plan on setting up multiple keys, keep the backup mounted or remember to terminate the GPG process before [saving](https://lists.gnupg.org/pipermail/gnupg-users/2016-July/056353.html).

10. Unmount, close, and disconnect the encrypted volume:

```console
$ sudo umount /mnt/encrypted-storage/

$ sudo cryptsetup luksClose secret
```

# Export Public Keys

**Important:** Without the *public* key, you will not be able to use GPG to encrypt, decrypt, nor sign messages. However, you will still be able to use YubiKey for SSH authentication.

Create another partition on the removable storage device to store the public key or reconnect networking and upload to a key server.

```console
$ sudo fdisk /dev/mmcblk0

Welcome to fdisk (util-linux 2.36.1).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Command (m for help): n
Partition number (2-128, default 2):
First sector (53248-30261214, default 53248):
Last sector, +/-sectors or +/-size{K,M,G,T,P} (53248-30261214, default 30261214): +25M

Created a new partition 2 of type 'Linux filesystem' and of size 25 MiB.

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.

$ sudo mkfs.ext2 /dev/mmcblk0p2

$ sudo mkdir /mnt/public

$ sudo mount /dev/mmcblk0p2 /mnt/public/

$ gpg --armor --export $KEYID | sudo tee /mnt/public/gpg-$KEYID-$(date +%F).asc
```

# Keyserver

(Optional) Upload the public key to a [public keyserver](https://debian-administration.org/article/451/Submitting_your_GPG_key_to_a_keyserver):

```console
$ gpg --send-key $KEYID

$ gpg --keyserver keys.gnupg.net --send-key $KEYID

$ gpg --keyserver hkps://keyserver.ubuntu.com:443 --send-key $KEYID
```

Or if [uploading to keys.openpgp.org](https://keys.openpgp.org/about/usage):

```console
$ gpg --send-key $KEYID | curl -T - https://keys.openpgp.org
```

# Configure Smartcard

Plug in a YubiKey and use GPG to configure it as a smartcard:

```console
$ gpg --card-edit

Reader ...........: Yubico Yubikey 4 OTP U2F CCID
Application ID ...: D2760001240102010006055532110000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 05553211
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......:
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 0 3
Signature counter : 0
KDF setting ......: off
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

Enter administrative mode:

```console
gpg/card> admin
Admin commands are allowed
```

**Note:** If the card is locked, see [Reset](#reset).
