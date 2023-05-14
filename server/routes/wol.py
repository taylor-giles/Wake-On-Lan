@app.post('/wol/{client_id}/{computer_id}', tags=['Wake On Lan'])
async def wake_on_lan(
    response: Response,
    current_user: AUTHENTICATED_USER,
    client_id: str,
    computer_id: str
):
    ''' Send the wake on lan command '''

    return {
        'client_id': client_id,
        'computer_id': computer_id,
        'message': 'WOL!'
    }