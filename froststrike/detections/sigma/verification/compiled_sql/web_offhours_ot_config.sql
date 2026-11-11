SELECT * FROM logs WHERE `cs-method`='POST' AND (`c-uri` LIKE '%/setpoint%' ESCAPE '\' OR `c-uri` LIKE '%/defrost%' ESCAPE '\' OR `c-uri` LIKE '%/alarm%' ESCAPE '\')
