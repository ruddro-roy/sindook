# OSS-Fuzz integration

These files are the sindook project definition for [google/oss-fuzz](https://github.com/google/oss-fuzz). They live here so the fuzzing setup is reviewed with the code it fuzzes; the copy of record goes in the OSS-Fuzz repo.

To submit: fork google/oss-fuzz, copy these three files to `projects/sindook/`, and open a PR. `primary_contact` must be a Google-account-verifiable email of a maintainer. Test locally first:

    python infra/helper.py build_image sindook
    python infra/helper.py build_fuzzers sindook
    python infra/helper.py check_build sindook

Six native Go targets: four box header/payload parsers, the armor decoder, and X-Wing decapsulation.
