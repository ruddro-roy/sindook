# typed: strict
# frozen_string_literal: true

# Homebrew formula for Sindook.
#
# This formula installs the prebuilt, CGO-free release binaries only; there
# is intentionally no `depends_on "go"` and nothing is compiled here.
#
# The four `sha256` values below are the SHA-256 digests of the published
# release archives from the release's checksums.txt. They are bumped for
# each release by scripts/fill-package-hashes.sh VERSION.
#
# Project-local formula: Sindook is not yet in homebrew-core (upstream
# submission is a future step). Install directly with:
#   brew install ./packaging/homebrew/sindook.rb
class Sindook < Formula
  desc "Hybrid post-quantum file encryption (X-Wing: X25519 + ML-KEM-768)"
  homepage "https://github.com/ruddro-roy/sindook"
  version "0.11.1"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_amd64.tar.gz"
      sha256 "eece5a1d904e1ced7672db1feba8bf9fc6612f6eab2208fc6a0387ed160a5c6d"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_arm64.tar.gz"
      sha256 "5cfe50867d7c1ca989f715dd3fcc69da73b5d9678c4e9b628778453562084eee"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_amd64.tar.gz"
      sha256 "5bfc61f80bc50185896c122f6765b8aedef96335b444149dcfbb4d90cf3ea2ad"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_arm64.tar.gz"
      sha256 "d9a46b05b32efc89280b74fd678f98d07c3ff44c35f8df90566b4de8e69cd2d5"
    end
  end

  def install
    bin.install "sindook"
    generate_completions_from_executable(bin/"sindook", "completion")
  end

  def caveats
    <<~EOS
      Verify the installation with:
        sindook version
        sindook doctor
        sindook selftest

      Sindook is pre-1.0 and has not received an independent security audit.
    EOS
  end

  test do
    assert_match(/^sindook #{Regexp.escape(version)}/, shell_output("#{bin/"sindook"} version"))
    system bin/"sindook", "selftest"
  end
end
