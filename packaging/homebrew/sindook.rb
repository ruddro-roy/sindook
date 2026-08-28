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
  version "0.10.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_amd64.tar.gz"
      sha256 "6dd4e54e09f9900815264990d4c62c5cbbca2b7f30afe328805e5c281505e369"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_arm64.tar.gz"
      sha256 "b94a1309e377fcad97ab1db98a059e5abf6985e4e236d7144a376b5ef6470a0d"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_amd64.tar.gz"
      sha256 "1b2970c3e7530d47d71e66e6c21f57cfad441598f6f9b0f1b41da82ed759fc85"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_arm64.tar.gz"
      sha256 "681347796cf7d994be3656b4a7eb53a388ca72c5c5a20f027a012d2f544549c5"
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
