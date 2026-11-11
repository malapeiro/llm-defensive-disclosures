SELECT * FROM logs WHERE (event LIKE 'login\_success' ESCAPE '\' AND cred_class='default') OR event LIKE 'service\_login\_success' ESCAPE '\'
