# Homebrew formula for Sindook.
#
# This formula installs the prebuilt, CGO-free release binaries only; there
# is intentionally no `depends_on "go"` and nothing is compiled here.
#
# IMPORTANT: the two `sha256` placeholders below MUST be filled at release
# time (see docs/RELEASING.md). Compute them from the published archives:
#   shasum -a 256 sindook_0.5.0_darwin_amd64.tar.gz
#   shasum -a 256 sindook_0.5.0_darwin_arm64.tar.gz
class Sindook < Formula
  desc "Hybrid post-quantum file encryption (X-Wing: X25519 + ML-KEM-768)"
  homepage "https://github.com/ruddro-roy/sindook"
  license "Apache-2.0"
  version "0.5.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_amd64.tar.gz"
      # FIXME(release): fill the SHA-256 of the amd64 archive at release time
      sha256 "" # shasum -a 256 sindook_0.5.0_darwin_amd64.tar.gz
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_darwin_arm64.tar.gz"
      # FIXME(release): fill the SHA-256 of the arm64 archive at release time
      sha256 "" # shasum -a 256 sindook_0.5.0_darwin_arm64.tar.gz
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_amd64.tar.gz"
      # FIXME(release): fill the SHA-256 of the linux amd64 archive at release time
      sha256 "" # shasum -a 256 sindook_0.5.0_linux_amd64.tar.gz
    else
      url "https://github.com/ruddro-roy/sindook/releases/download/v#{version}/sindook_#{version}_linux_arm64.tar.gz"
      # FIXME(release): fill the SHA-256 of the linux arm64 archive at release time
      sha256 "" # shasum -a 256 sindook_0.5.0_linux_arm64.tar.gz
    end
  end

  def install
    bin.install "sindook"
    bash_completion.install Utils.safe_popen_read(bin/"sindook", "completion", "bash") => "sindook"
    zsh_completion.install Utils.safe_popen_read(bin/"sindook", "completion", "zsh") => "_sindook"
    fish_completion.install Utils.safe_popen_read(bin/"sindook", "completion", "fish") => "sindook.fish"
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
    assert_match(/^sindook #{version}/, shell_output("#{bin}/sindook version"))
  end
end
