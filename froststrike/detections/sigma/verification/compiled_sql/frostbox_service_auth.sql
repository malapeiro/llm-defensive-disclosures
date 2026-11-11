SELECT * FROM logs WHERE event LIKE 'AUTH\_SERVICE\_CODE' ESCAPE '\' AND outcome='success'
