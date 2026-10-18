#!/bin/sh
# CB-BUF-HYG-002 / reminder - remind staff to swap utensils every CB_INTERVAL_MIN minutes.
# SPDX-License-Identifier: Apache-2.0
set -eu
: "${CB_INTERVAL_MIN:?parameter interval_min is required}"

printf '*/%s * * * * root wall "Swap the serving utensils"\n' "$CB_INTERVAL_MIN" \
  > /etc/cron.d/cirsec-buffet-utensils
