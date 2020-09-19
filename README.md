Mnemonic Shamirs Secret Sharing
===============================

Generate and recover master secret using shared secrets.

The algorithm to generate and recover secrets is derived from
original __Shamir's Secret Sharing__ [^Shamirs Secret Sharing] procedure.

A random master secret will be created and converted into a list of
short english words that are hard to confuse with any other
possible words ( find all 1024 words in `wordlist.txt` ).

Create a master secret that can be recovered using 3 out of 9 shared secrets :

	mnemonic_shamirs_secret_sharing.py generate --min-shares 3 --nof-shares 9

If you want a master secret that is using more bits, use `--long` option:

	mnemonic_shamirs_secret_sharing.py generate --long --min-shares 3 --nof-shares 9

Another variant, using created docker image:

	docker build -t mnemonic_shamirs_secret_sharing .
	docker run --rm  mnemonic_shamirs_secret_sharing -- generate --min-shares 3 --nof-shares 9

To recover master secret, put given number of minimum required shared secrets into one
file, separated by empty lines and execute tool :

	mnemonic_shamirs_secret_sharing.py recover shared_secrets.txt

or input required shared secrets interactively one after another on console :

	mnemonic_shamirs_secret_sharing.py recover --interactive

or using docker image :

    docker run --rm -i  mnemonic_shamirs_secret_sharing -- recover --interactive

There is a `sample*.txt` that contain

- master secret in commented lines at beginning of file
- 9 shared secrets, where 3 are required to recover that master secret

You can play around using this file by commenting out some of the shared secrets
to see how it can be used and what happens when there are too few shared secrets
provided and recovering therefore fails.

## Example use case for this procedure

Bob creates a master secret with a total of 9 shared secrets und
selects that in order to recover master secret, 3 shared secrets must be combined.

After generating master and shared secret using the tool
Bob now has a master secret

	velvet forbid literary shadow equip mother unfair adequate velvet custody
	flip avoid black

and nine shared secrets

1:

	curious document location acrobat ecology arcade process frost capture
	revenue symbolic exact juice vexed float answer early again

2:

	coal axle behavior adjust ecology research remember learn vegan render
	cargo human privacy spill devote kitchen downtown alto

3:

	ceiling dilemma extra adult ecology anatomy insect should hour sharp
	pleasure payroll friendly oven chubby triumph reject acid

4:

	advocate smell hunting agree leaves voice theory domain modern triumph
	lamp training loud eyebrow carve fiber rebuild ajar

5:

	member column income airport royal lift again soldier game capital
	omit dwarf crucial twin crunch replace dictate acid

6:

	carbon grief species alien ecology profile sprinkle member spend
	glimpse adult physics estimate hunting entrance campus dilemma already

7:

	aunt soldier priest already royal juice force index username rescue
	quantity carve ticket sweater indicate keyboard regret advocate

8:

	raspy tolerate parcel ambition royal therapy mental language rainbow
	clock prepare pleasure welcome demand promise staff repeat agree

9:

	afraid failure realize amuse leaves uncover iris prune change parcel
	unkind ending maiden idea wildlife daisy duckling admit

Bob uses his master secret to secure some important information.
Afterwards he distributes different shared secrets to some other trusted people :

| Shared Secret | Person |
|:-------------:|:------:|
|       1       |  Lisa  |
|       2       |  Peter |
|       3, 4    |  Alice |
|       5       |  John  |
|       6       |  Anne  |
|       7       |  Luke  |

He can distribute remaining two shared secrets later if necessary.

If enough number of parties join and provide their shared secrets
( at least three are required, order of how a single shared secret is contributed
is arbitrary ), then algorithm can recover the original
master secret and hence the original secured information of Bob can be recovered.

Notice that e.g. Alice only needs one other party to have in total
three shared secrets to recover master secret.

If less than three shared secrets are used during recovering attempt,
the result will _not_ be the original master secret !

A single shared secret is of no use, only combination of sufficient number
of shared secrets can be used to recover master secret.

[^Shamirs Secret Sharing]: Wikipedia https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
[^Shamirs Secret Sharing Paper]: Shamirs Original Paper https://groups.csail.mit.edu/cis/crypto/classes/6.857/papers/secret-shamir.pdf
