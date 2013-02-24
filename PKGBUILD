# Maintainer: Andrea Bontempi <andreabont@yahoo.it>
pkgname=projectriddle-git
pkgver=20130224
pkgrel=1
pkgdesc="Modular Network Packet Sniffer"
arch=('i686' 'x86_64')
url="http://github.com/Andreabont/Project-Riddle"
license=('GPL')
depends=('boost' 'libpcap')
makedepends=('git')

_gitroot=git://github.com/Andreabont/Project-Riddle.git
_gitname=Project-Riddle

build() {
  cd "$srcdir"
  msg "Connecting to GIT server...."

  if [[ -d "$_gitname" ]]; then
    cd "$_gitname" && git pull origin
    msg "The local files are updated."
  else
    git clone "$_gitroot" "$_gitname"
  fi

  msg "GIT checkout done or server timeout"
  msg "Starting build..."

  rm -rf "$srcdir/$_gitname-build"
  git clone "$srcdir/$_gitname" "$srcdir/$_gitname-build"
  cd "$srcdir/$_gitname-build"

  mkdir build
  cd build
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DSYSCONF_INSTALL_DIR=/etc
  make
}

package() {
  cd "$srcdir/$_gitname-build/build"
  make DESTDIR="$pkgdir/" install
}
