for i in {1..15}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://waf.test.local:8081/;
done