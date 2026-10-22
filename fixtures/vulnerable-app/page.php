<?php
include($_GET['page']);
mysqli_query($db, "SELECT * FROM t WHERE id=" . $_GET['id']);
