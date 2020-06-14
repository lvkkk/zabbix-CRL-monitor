# Zabbix-CRL-monitor
<h1>
Описание</H1>
Проект содержит шаблон для Zabbix v4.4 и скрипт на Python3, который на основании заданых в Zabbix данных о списке отзыва производит обращение к точке публикации и извлечение информации об оставшемся времени действия, которую он передает обратно в Zabbix. Скрипт позволяет проводить проверку списков отзыва только в формате DER.
Тестировалась работа только со списками отзыва УЦ КриптоПро. Не работает по HTTPS.
<img src="5.png" /><h1>
Установка</H1><ul><li>
Импортируйте шаблон <b><i>zbx_crlmonitor_template.xml</i></b> в свой сервер Zabbix</li><li>
Добавьте узел содержащий описание списка отзыва со следдующими полями:<br />
Впишите рабочий адрес и порт в соответствующие поля настроек узла.<img src="1.png" /><br />
Прикрепите к узлу шаблон  <b><i>Template CRL expiration</b></i><img src="2.png" /> <br />
Создайте макрос {$PATH} описывающий путь к сертифкату относительно веб-сервера<img src="3.png" /><br />
Установите узлу тег <b><i>crl</b></i> со значением <b><i>yes</b></i><img src="4.png" /><br /></li><li>
Установите в заголовке скрипта <b><I>api.py</i> </b>параметры доступа к интерфесу Zabbix и перенесети его на сервер с которого доступны списки отзыва и сервер Zabbix. Обратите внимание, что путь к api_jsonrpc.php, может быть относительно корня или каталога /zabbix/</li><li>
Создайте задачу периодического запуска скрипта. Триггер в шаблоне настроен на срабатывание в случае отсутсвия данных более 30 минут.</li></ui>
