for i in {1..200}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://waf.test.local:80/;
done