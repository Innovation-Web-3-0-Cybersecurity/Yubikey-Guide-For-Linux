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

Verify the signature of the hashes file with GPG:

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

Ensure the SHA512 hash of the live image matches the one in the signed file - if there following command produces output, it is correct:

```console
$ grep $(sha512sum debian-live-*-amd64-xfce.iso) SHA512SUMS
SHA512SUMS:3c74715380c804798d892f55ebe4d2f79ae266be93df2468a066c192cfe1af6ddae3139e1937d5cbfa2fccb6fe291920148401de30f504c0876be2f141811ff1  debian-live-12.2.0-amd64-xfce.iso
```

See [Verifying authenticity of Debian CDs](https://www.debian.org/CD/verify) for more information.

Mount a storage device and copy the image to it:

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