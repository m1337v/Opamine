# RootHide 3 integration scope

- Date: 2026-10-25 (Asia/Bangkok).
- Authorization: user requested merging `roothide/Dopamine-roothide` and verifying the modified implementation, with Astra and Daybreak Blue advisors.
- Repository: `m1337v/Opamine`, local `rhinject` checkout.
- Starting commit: `1cabcbf0df1a552e3794a75f4b125ebe0a20a1dc` plus the existing September runtime fixes.
- Preserved baseline: `2e2ebab` records those runtime fixes before the merge.
- Upstream: `roothide/Dopamine-roothide`, branch `3.x`, commit `24ea745b33cd3a1eba9b7196a875e42eed1fa34e`, based on Dopamine 3.0.12.
- In scope: local source integration, dependency revision alignment, host tests, iPhoneOS builds, package inspection, and a local merge commit.
- Device state: no target-device execution or reboot performed during this integration. The previously affected iPhone15,3/iOS 16.2 requires separate runtime validation.
- Publication: no remote push or release publication performed.
