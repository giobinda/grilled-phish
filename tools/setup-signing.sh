#!/usr/bin/env bash
# One-time setup of the approval step for signing the well-known sites list.
# Run it AFTER making the repository public (approval rules on private
# repositories need a paid GitHub plan).
#
#   tools/setup-signing.sh [path/to/list-signing-key.pem]
#
# It creates the GitHub environment "list-signing" that:
#   - requires YOUR approval before the sign job runs,
#   - can only be used from the main branch,
#   - holds the private signing key as a secret (readable only by that job).
set -euo pipefail

KEY="${1:-$HOME/.config/grilled-phish/list-signing-key.pem}"
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
ENV_NAME="list-signing"

[ -f "$KEY" ] || { echo "Signing key not found: $KEY" >&2; exit 1; }
if [ "$(gh api "repos/$REPO" -q .private)" = "true" ]; then
  echo "$REPO is still private. Make it public first, then run this again." >&2
  exit 1
fi

ME_ID="$(gh api user -q .id)"
echo "Creating environment '$ENV_NAME' on $REPO (reviewer: $(gh api user -q .login))…"
gh api -X PUT "repos/$REPO/environments/$ENV_NAME" --input - >/dev/null <<EOF
{
  "reviewers": [{ "type": "User", "id": $ME_ID }],
  "prevent_self_review": false,
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
EOF
gh api -X POST "repos/$REPO/environments/$ENV_NAME/deployment-branch-policies" \
  -f name=main -f type=branch >/dev/null 2>&1 || true

echo "Storing the signing key as an environment secret…"
gh secret set LIST_SIGNING_KEY --repo "$REPO" --env "$ENV_NAME" < "$KEY"

# Fail loudly if the protection didn't stick: an environment WITHOUT a required
# reviewer would let the key be used with no approval.
RULES="$(gh api "repos/$REPO/environments/$ENV_NAME" -q '[.protection_rules[].type] | join(",")')"
case "$RULES" in
  *required_reviewers*) echo "Done. Protection rules: $RULES" ;;
  *) echo "WARNING: required reviewer NOT active (rules: '$RULES'). Deleting the secret." >&2
     gh secret delete LIST_SIGNING_KEY --repo "$REPO" --env "$ENV_NAME"; exit 1 ;;
esac
echo
echo "Recommended: protect the main branch (Settings > Branches) so workflow changes need a pull request."
