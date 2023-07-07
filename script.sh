        #!/usr/bin/env bash
        if [[ $(params.verbose) = "true" ]]; then
          set -x
        fi
        curl -s $(params.list-url) -o trusted.txt

        for elem in $@; do
          list=trusted.txt
          dockerregex="^docker://"
          httpsregex="^https://"
          if [[ $elem =~ $dockerregex ]]; then
            # we only extract the registry name for the moment
            # thus you won't be able to whitelist specific repositories on i.e. dockerhub
            compare=`echo $elem | cut -d: -f2 | cut -d/ -f3`
            grep $compare $list

          elif [[ $elem =~ $httpsregex ]]; then
            # we allow git sources to be specified at a toplevel
            # for other schematas adapt the code
            # https://github.com/company/projecta/projectb will be shortened to
            # https://github.com/company and compared afterwards

            compare=`echo $elem | cut -d/ -f 1-4`
            grep $compare $list
          # ToDo add git ssh possibility
          else
            echo "invalid element $elem"
            exit 1
          fi

          if [ $? -ne 0 ]; then
            echo '$compare not in list'
            exit 1
          fi
        done