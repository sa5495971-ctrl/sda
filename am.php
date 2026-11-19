<?php $c=['date'=>'date','whoami'=>'whoami','uptime'=>'uptime']; $k=$_GET['cmd']??''; if(isset($c[$k])) echo '<pre>'.htmlspecialchars(shell_exec($c[$k])).'</pre>'; ?>
