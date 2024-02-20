## build

    docker build -t mk-orange-dhcp-auth:0.1 .

## run

Populate a `credentials` file like this one:

    # user:password
    fti/xxxxx:xxxxx

Then run:

    docker run -v $PWD/credentials:/credentials -e CREDENTIALS=/credentials -p 8000:8000 mk-orange-dhcp-auth:0.1


A simple curl call should give you a hash:

    curl -i -H 'Accept: application/json' http://127.0.0.1:8000/api/hash
