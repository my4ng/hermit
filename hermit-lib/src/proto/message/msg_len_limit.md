# Message Length Limit

This is a note on the message length limit part of the protocol.

The **Message Length Limit (MLL)** determines the upper bound on the message payload's size. Since all plain messages must have a fixed length below the `MIN_LEN_LIMIT`, this is primarily concerned with secure messages.

At initialization, `MIN_LEN_LIMIT` is set for both sides, and either side may send an `AdjustMessageLengthRequest` plain message to request the MLL to be changed to the limit included in the message. The range of valid limits is:

`MIN_LEN_LIMIT` <= `len_limit` <= `MAX_LEN_LIMIT`

If the requested limit is not within this range, the other side MUST reject the request, and maintain the current limit.

If the requested limit is within the range, and less than or equal to the current limit, the other side MUST accept the request. If however the limit is greater, the other side MAY choose to either accept or reject the request at their discretion.

The acceptance/rejection response is sent back through the `AdjustMessageLengthResponse` plain message, with any accepted limit include. Both sides must change the MLL if and only if AFTER sending/receiving this message. During the period between sending the request and waiting for the response, the side MUST reject any MLL adjustment request for the other side.
