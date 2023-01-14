<?php

require $_SERVER['DOCUMENT_ROOT'] . '/php/app.php';

if (isset($_POST['email'])) {
    $em = clean($_POST['email'], "lo");
    $em = filter_var($em, FILTER_SANITIZE_EMAIL);

    if (!filter_var($em, FILTER_VALIDATE_EMAIL)) {
        $ms = "No valid email in post";
        goto end;
    } else {
        $ems = spe($em, 'e');
        $eme = enc($ems, 'e');
        $emh = xhash($eme);

        $uex = ckex(
            // check if email from post exists in db
            $sv,
            $un,
            $pw,
            $db, $sel = 'email',
            $tn, $whr = 'email', $val = $ems
        );

        if (!$uex) {
            //~ Email not in DB -> visitor

            if (!cset('t')) {
                // set visitor trial-cookie if not set yet
                $tc = enc('1', 'e');
                setcookie('t', $tc, dur(60 * 60));

                $jres = "no";
                goto end;
            } else {
                $tc = enc($_COOKIE['t'], 'd'); // decode cookie t first

                if ($tc > '4') {
                    /* block visitor if time-cookie is above 4,
                    resulting from to many trials to reset pass or log in */
                    $jres = "bk";
                    goto end;
                } else {
                    /* maximum trials not reached:
                    add 1 to trial-cookie and set as cookie */
                    $tc = ($tc + 1);
                    $tc = enc($tc, 'e');
                    setcookie('t', $tc, dur(60 * 60));
                }
            }
        } else {
            //~ Email in DB -> existing user

            $conn = mysqli_connect($sv, $un, $pw, $db);
            if (mysqli_connect_errno()) {
                $ms = 'ERROR: No conn to db "'
                . $db . '"-' . mysqli_connect_error();
                goto end;
            }

            $hex = bin2hex(random_bytes(32)); // generate random number
            $hhx = enc($hex, 'e'); // encode the random number
            $nth = xhash($hhx); // hash the encoded random nuber
            /* urlencode the encoded hashed random number
            just to be attached to the reset link in the sent email */
            $enth = urlencode($nth);
            $rstp = $wa . "/#/res?h=" . $enth; // reset-link to be sent to v

            mail(
                $em, "Reset password", "\nClick the password reset link:\n\n" . $rstp . "\n\n", $from
            );

            // update db "unix" column, with fresh nt, for later comparison
            mysqli_query(
                $conn, "UPDATE " . $tn . " SET unix='"
                . $nt . "' WHERE email ='" . $ems . "'"
            );

            // update the db "ulog" column, with the hashed random number
            mysqli_query(
                $conn, "UPDATE " . $tn . " SET ulog='"
                . $nth . "' WHERE email ='" . $ems . "'"
            );

            /* set cookie with the encoded random number (not hashed)
            for later comparison when reseting the password */
            setcookie('q', $hhx, dur(60 * 60));

            $jres = "rs"; //~ all good > reset link sent
            goto end;

        }
    }
}

end:

if ($ms) {
    lg($lg, $p, $tm, $ms);
}

if (isset($conn->server_info)) {
    mysqli_close($conn);
}

echo $jres;