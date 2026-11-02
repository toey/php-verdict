<?php
// ordinary template code: must score CLEAN
function rtp_title( $post_id ) {
	$t = get_the_title( $post_id );
	return esc_html( strtoupper( $t ) );
}
echo rtp_title( get_the_ID() );
