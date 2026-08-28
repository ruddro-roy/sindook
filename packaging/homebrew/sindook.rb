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
  version "0.9.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_amd64.tar.gz"
      sha256 "77175c09d410818afa2fe46c692ed4239db8c45a349697481d282bd31e50f194"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_arm64.tar.gz"
      sha256 "4934d620da32023eb351e7bba953e27547afe7521e0c24cc8d0ff4732d647741"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_amd64.tar.gz"
      sha256 "c3dcdab6f8394887489c3434d0883db85f72c5b35cf86ac4eddec2414c977def"
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_arm64.tar.gz"
      sha256 "49c9f103c2cd264fa67fcef0e6da5188332298ca4b82b35c1f66c368d3b2f822"
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
