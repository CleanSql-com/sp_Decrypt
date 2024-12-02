USE [TestDecryption];
GO

SET NOCOUNT ON;
DECLARE
  --@objectid    INTEGER = OBJECT_ID(N'dbo.p_TestEncryption')
    @objectid    INTEGER = OBJECT_ID(N'dbo.p_TestEncryption_Short', N'P')
  , @SessionId   INT
  , @ErrorMsg    NVARCHAR(MAX)
  , @family_guid BINARY(16)
  , @objid       BINARY(4)
  , @subobjid    BINARY(2)
  , @imageval    VARBINARY(MAX)
  , @RC4Key      BINARY(20);


SELECT      @SessionId = ses.session_id
FROM        sys.endpoints AS en
INNER JOIN  sys.dm_exec_sessions ses ON en.endpoint_id = ses.endpoint_id
WHERE       en.name = 'Dedicated Admin Connection';

IF (@@SPID <> (COALESCE(@SessionId, 0)))
BEGIN
    SET @ErrorMsg
        = N'In order to run this script you need to connect using Dedicated Admin Connection (DAC).';
    RAISERROR(@ErrorMsg, 16, 1);
    RETURN;
END


/* Find the database family GUID: */
SELECT @family_guid = CONVERT(BINARY(16), [DRS].[family_guid])
FROM [sys].[database_recovery_status] AS [DRS]
WHERE [DRS].[database_id] = DB_ID();

IF (@objectid IS NOT NULL)
BEGIN
    /* Convert object ID to little-endian binary(4): */
    SET @objid = CONVERT(BINARY(4), REVERSE(CONVERT(BINARY(4), @objectid)));

    SELECT
        /* Read the encrypted value: */
        @imageval = [sov].[imageval]
        /* get the subobjid and convert to little-endian binary: */
      , @subobjid = CONVERT(BINARY(2), REVERSE(CONVERT(BINARY(2), [sov].[subobjid])))
    FROM [sys].[sysobjvalues] AS [sov]
    WHERE [sov].[objid] = @objectid
    AND   [sov].[valclass] = 1;

    /* Compute the RC4 initialization key: */
    --SELECT HASHBYTES('SHA1', (0x2556AD936B8C3947876B08258F5EB3C3 + 0x6BD9DF19 +	0x0100))
    SET @RC4Key = HASHBYTES('SHA1', @family_guid + @objid + @subobjid);

    EXEC [dbo].[uspDecodeRc4] @RC4Key = @RC4Key, @EncryptedText = @imageval, @ObjectId = @objectid, @DebugMode = 1;
END;
ELSE
BEGIN
    RAISERROR('Could not find objectid for the object name/object type specified', 16, 1);
END;
