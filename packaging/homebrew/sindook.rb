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
  version "0.7.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_amd64.tar.gz"
      sha256 "d46acda1fc174e7841c4a9d542ac5718c2efb4860f197ff18349fdafac58421b"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_arm64.tar.gz"
      sha256 "66d6ac7ce60f1832148a76f7fc742c6a5d8e4359ab8cd4406db0c6c25d947dd1"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_amd64.tar.gz"
      sha256 "42c3c286b7c095986f10fec809315dbb7dd94910df78b43bb81bdd4bbfda1f91"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_arm64.tar.gz"
      sha256 "c50a22b785ea3dd7bd416e491afb56bfff88b615cf3622272b103a9ea3b2a6c3"
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
    assert_match(/^sindook #{Regexp.escape(version)}/, shell_output("#{bin}/sindook version"))
    system "#{bin}/sindook", "selftest"
  end
end
