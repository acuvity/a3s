package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/manipulate"
)

// A NamespaceDeletionRecordsProcessor is a bahamut processor for NamespaceDeletionRecord.
type NamespaceDeletionRecordsProcessor struct {
	manipulator manipulate.Manipulator
}

// NewNamespaceDeletionRecordsProcessor returns a new NamespaceDeletionRecordsProcessor.
func NewNamespaceDeletionRecordsProcessor(manipulator manipulate.Manipulator) *NamespaceDeletionRecordsProcessor {
	return &NamespaceDeletionRecordsProcessor{
		manipulator: manipulator,
	}
}

// ProcessRetrieveMany handles the retrieve many requests for NamespaceDeletionRecord.
func (p *NamespaceDeletionRecordsProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.NamespaceDeletionRecordsList{})
}
