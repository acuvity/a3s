package indexes

import (
	"log/slog"
	"strings"

	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	bson "go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongooptions "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Ensure ensures the indexes declared in the specs are aligned.
func Ensure(m manipulate.Manipulator, model elemental.ModelManager, packageName string) (err error) {

	indexes := GetIndexes(packageName, model)

	for ident, mIndexes := range indexes {
		if err = manipmongo.EnsureIndex(m, ident, mIndexes...); err != nil {
			slog.Warn("Unable to ensure index", err)
		}
	}

	return nil
}

// GetIndexes returns all the indexes for all the identity in the model
func GetIndexes(packageName string, model elemental.ModelManager) (mIndexes map[elemental.Identity][]mongo.IndexModel) {

	var indexes [][]string

	mIndexes = map[elemental.Identity][]mongo.IndexModel{}

	for _, ident := range model.AllIdentities() {

		if ident.Package != packageName {
			continue
		}

		indexes = model.Indexes(ident)
		if len(indexes) == 0 {
			continue
		}

		iName := "index_" + ident.Name + "_"

		for i := range indexes {

			keys := bson.D{}
			opts := mongooptions.Index()

			piName := iName
			var hashedApplied bool
			keyNames := []string{}

			for _, name := range indexes[i] {

				if hashedApplied {
					panic("hashed index must not be a compound index")
				}

				switch name {

				case ":shard":
					piName = "shard_" + iName

				case ":unique":
					opts.SetUnique(true)

				default:

					name = strings.ToLower(name)
					if attSpec, ok := model.Identifiable(ident).(elemental.AttributeSpecifiable); ok {
						if bsonName := attSpec.SpecificationForAttribute(name).BSONFieldName; bsonName != "" {
							name = bsonName
						}
					}

					keyName := name
					keyValue := any(int32(1))
					if strings.HasPrefix(name, "$hashed:") {
						hashedApplied = true
						keyName = strings.TrimPrefix(name, "$hashed:")
						keyValue = "hashed"
					}

					keys = append(keys, bson.E{Key: keyName, Value: keyValue})
					keyNames = append(keyNames, keyName)
				}
			}

			name := piName + strings.Join(keyNames, "_")
			opts.SetName(name)

			mIndexes[ident] = append(mIndexes[ident], mongo.IndexModel{Keys: keys, Options: opts})
		}
	}

	return mIndexes
}
