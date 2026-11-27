# aura-sbom-action

Generate a CycloneDX 1.6 SBOM from a repository lockfile and upload it to an Aura
product. Generation uses a pinned sbomify container in standalone mode and does
not require a sbomify account. The Aura API key is supplied only to the upload
step.

## Use in a workflow

Run on a Linux runner with Docker, Python 3.9 or newer (for example,
`ubuntu-latest`), and outbound HTTPS access. The runner must be able to pull
the generator image from GitHub Container Registry and reach your Aura origin.
On a cold cache the generator also downloads attestation-verified tool bundles
from [sbomify's GitHub releases](https://github.com/sbomify/sbom-tools/releases).
Metadata enrichment may contact package registries. Standalone mode does not
mean offline mode.

Check out your repository at the default workspace root first, without persisting
checkout credentials. Replace `FULL_SHA` with the full commit SHA of a reviewed
version of this action; don't use a moving branch or tag.

```yaml
name: Aura SBOM
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  upload:
    if: github.ref_protected
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a
        with:
          persist-credentials: false
      - uses: Linuscent/aura-sbom-action@FULL_SHA
        with:
          lockfile: package-lock.json
          product-id: ${{ vars.AURA_PRODUCT_ID }}
          aura-origin: ${{ vars.AURA_ORIGIN }}
          api-key: ${{ secrets.AURA_SBOM_API_KEY }}
          release-version: ${{ github.ref_type == 'tag' && github.ref_name || '' }}
```

| Input | Required | Description |
| --- | --- | --- |
| `lockfile` | Yes | Supported readable file, relative to the repository root (for example, `apps/web/pnpm-lock.yaml`). Symlinks must not resolve outside the workspace. |
| `product-id` | Yes | The destination Aura product ID, not the GitHub repository ID. |
| `aura-origin` | Yes | The trusted Aura HTTPS origin (for example, `https://aura.example.com`), with no path except an optional trailing slash. No credentials, query, or fragment. |
| `api-key` | Yes | An Aura workspace API key with SBOM upload permission. Pass it from a GitHub Actions secret, never inline or as a job-level environment variable. |
| `release-version` | No | Defaults to empty, preserving the generated version. A nonempty value replaces the declared version when the SBOM has a root metadata component. |

Supported filenames: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
`bun.lock`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`,
`Cargo.lock`, `go.mod`, `go.sum`, `Gemfile.lock`, `composer.lock`,
`packages.lock.json`, `pubspec.lock`, `conan.lock`, and `Package.resolved`.
The action writes `aura-sbom.cdx.json` to the workspace root. That path must not
already exist when the action starts. Both the file and the serialized upload
request are limited to 10 MiB.

## Trust and reruns

Run only on trusted refs, not on untrusted pull request code. Trust the
repository checkout, all other steps in the job, the runner, and the configured
Aura origin: the upload sends your key to that origin. When the key is a
repository Actions secret, **all repository writers must be trusted with the
key's workspace access**. Writers can use the secret in a different workflow;
the protected-ref condition in the example limits only that job. The product
input identifies a destination; it does not narrow the key's permissions.

The pin fixes the generator container, not every tool it downloads. The pinned
image's [tool configuration](https://github.com/sbomify/sbomify-action/blob/c833c95d975c1fe5ba6ad2339146ef5676611ba1/sbomify_action/tools.toml)
uses the rolling `tools-rolling` release for cdxgen. Attestation verification
checks provenance; it does not make that rolling release immutable.

A verified `202` receipt means Aura accepted the upload and created a release;
it does not mean analysis is finished. Every accepted upload creates a distinct
release, even with identical content or the same declared version. The action
does not follow redirects or retry automatically. If the outcome is unknown
(for example, after a timeout), inspect the product's releases before rerunning.

## Tests

Run the Python standard-library tests from the action repository root. They use
synthetic fixtures and mocked HTTP; no Aura instance or credentials are needed.

```sh
python3 -B -m unittest discover -s tests -v
```

The GitHub-hosted smoke harness (`tests/github_smoke.py`) uses OpenSSL and a
loopback HTTPS mock. It needs no production or test-instance credentials and
does not contact Aura. The generation step still needs the outbound access
described above. The smoke job should trust `AURA_SMOKE_CERT` on the disposable
runner host for the upload; do not pass a host-only CA file path into the Docker
generator's environment.
