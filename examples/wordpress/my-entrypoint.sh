#!/bin/bash

<< COMMENTOUT
Description:
This entry point will run wp-cron periodically using cron installed on the original nginx image, and will execute the entry point of the original nginx image.
COMMENTOUT

(crontab -l 2> /dev/null; echo "* * * * * /usr/local/bin/php /var/www/html/wp-cron.php") | crontab -
cron
/usr/local/bin/docker-entrypoint.sh "$@"