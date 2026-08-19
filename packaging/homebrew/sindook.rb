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
  version "0.8.1"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_amd64.tar.gz"
      sha256 "b8e3b216cf4587c3c2a29a53f12bffda1ce147c10d4ca777120f83c9d3b498c3"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_arm64.tar.gz"
      sha256 "5a2ea70e0386db177fd8b8cb0d3ba72ebf95307550b9acb27caef2197ac82110"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_amd64.tar.gz"
      sha256 "af7c9fdde47e97ba8c27044d83fc3b18d908154b3eccef79d4ddb9ba54ffbebe"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_arm64.tar.gz"
      sha256 "2903c49b861a5ee6e234c9e638da0f3face81a1acb5adc277d607a6826f3f4b0"
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
